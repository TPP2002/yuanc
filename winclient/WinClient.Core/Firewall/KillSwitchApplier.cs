using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WinClient.Core.Firewall;

public sealed record PatrolReport(IReadOnlyList<string> Reenforced, IReadOnlyList<string> NewlyDisabled, IReadOnlyList<string> MissingRules)
{
    public static PatrolReport Empty => new([], [], []);
    public bool Clean => Reenforced.Count == 0 && NewlyDisabled.Count == 0 && MissingRules.Count == 0;
}

public interface IKillSwitch
{
    Task ApplyAppsAsync(IReadOnlyList<string> programs) => throw new InvalidOperationException("当前断网保护不支持仅指定程序模式。");
    Task ApplyAppsAsync(IReadOnlyList<string> programs, IReadOnlyList<string> filterPrograms) => ApplyAppsAsync(programs);
    Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock) => PatrolAsync(expectedRules);
    Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock, CancellationToken token) => PatrolAsync(expectedRules, enforceDefaultBlock);
    string? PendingMode => null;
    Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules) => Task.FromResult(PatrolReport.Empty);
    bool HasPendingState { get; }
    Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null);
    Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port);
    Task RemoveAsync();
    Task<string?> RecoverAsync();
    Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null) =>
        realityPort == 443 ? ApplyAsync(ips, program, hy2Port, auth) : throw new InvalidOperationException("当前断网保护不支持此出口端口。");
    Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        realityPort == 443 ? UpdateNodeAsync(ips, program, hy2Port) : throw new InvalidOperationException("当前断网保护不支持此出口端口。");
}

public class FirewallIneffectiveException(string message) : InvalidOperationException(message);
public sealed class WfpUnavailableException(string message) : FirewallIneffectiveException(message);
public sealed class RouteGuardUnavailableException(string message) : FirewallIneffectiveException(message);

public sealed class KillSwitchApplier : IKillSwitch
{
    public const int VerifyFailedExitCode = 3;
    public const string WfpConnectRefused = "系统过滤层断网保护未能建立,已拒绝连接。请点击断开后重试,仍失败请联系管理员。";
    public const string WfpRemoveFailed = "系统过滤层断网保护未能撤销,网络可能仍被阻断;请重试断开或联系管理员。";
    public const string WfpPatrolFailed = "系统过滤层过滤器缺失且未能重建,断网保护可能失效,请联系管理员";
    public const string RouteConnectRefused = "兜底路由未能建立,隧道中断时虚拟机与 WSL 的流量可能直连,已拒绝连接。请点击断开后重试,仍失败请联系管理员。";
    public const string RouteRemoveFailed = "兜底路由未能撤销,网络可能仍不通;请重试断开或联系管理员。";
    public const string RoutePatrolFailed = "兜底路由缺失且未能重建,隧道中断时虚拟机与 WSL 的流量可能直连,请联系管理员";
    public const string ScriptTimedOut = "系统防火墙设置超过时限没有完成，已中止。";
    internal TimeSpan ScriptTimeout { get; init; } = TimeSpan.FromSeconds(180);
    private readonly ICommandRunner runner;
    private readonly Action<string>? log;
    private readonly IWfpEngine? wfp;
    private readonly string wfpOffPath;
    private readonly IRouteGuard? routes;
    private readonly string routeOffPath;
    private bool routesApplied;
    private IReadOnlyList<WfpFilterSpec>? wfpPolicy;
    private AuthEndpoint? lastAuth;
    private readonly SemaphoreSlim gate = new(1, 1);
    public string StatePath { get; }
    public bool HasPendingState => File.Exists(StatePath);
    public string? PendingMode
    {
        get
        {
            try
            {
                using var json = JsonDocument.Parse(File.ReadAllText(StatePath));
                return json.RootElement.TryGetProperty("mode", out var mode) ? mode.GetString() : "global";
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
            { return null; }
        }
    }
    public string AuditPath { get; }
    public string? LastRecoveryWarning { get; private set; }
    public KillSwitchApplier(string runDirectory, ICommandRunner? runner = null, IWfpEngine? wfp = null, IRouteGuard? routes = null, Action<string>? log = null)
    {
        this.runner = runner ?? new CommandRunner();
        this.wfp = wfp;
        this.routes = routes;
        this.log = log;
        routeOffPath = Path.Combine(runDirectory, "route-off");
        wfpOffPath = Path.Combine(runDirectory, "wfp-off");
        StatePath = Path.Combine(runDirectory, "killswitch-state.json");
        AuditPath = Path.Combine(runDirectory, "firewall-audit.json");
    }

    /// <summary>记录失败不能影响断网保护：记录口抛出的任何异常一律吞掉。</summary>
    private void WriteLog(string text)
    {
        if (log is null) return;
        try { log(text); }
        catch (Exception) { }
    }

    private static long ElapsedMilliseconds(long started) =>
        (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds;

    private static string FormatResultLog(string phase, CommandResult result, long started)
    {
        var text = $"防火墙脚本[{phase}] 退出码 {result.ExitCode}，用时 {ElapsedMilliseconds(started)} 毫秒";
        var summary = SanitizeError(result.Error);
        return result.ExitCode != 0 && summary.Length > 0 ? text + "，错误摘要：" + summary : text;
    }

    private static string FormatTimeoutLog(string phase, long started) =>
        $"防火墙脚本[{phase}] 超时，用时 {ElapsedMilliseconds(started)} 毫秒";

    private async Task AppendRecoveryLineAsync(string line)
    {
        try
        {
            var path = Path.Combine(Path.GetDirectoryName(StatePath)!, "killswitch-recovery.log");
            await File.AppendAllTextAsync(path, line + Environment.NewLine).ConfigureAwait(false);
        }
        catch (Exception) { /* 追加证据失败不能阻断恢复。 */ }
    }

    /// <summary>标准错误进日志前必须脱敏：折叠换行、隐去 IPv4 地址与用户目录名，超长截断。</summary>
    public static string SanitizeError(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;
        var value = Regex.Replace(text, @"(?:\r\n|\r|\n)+", " | ");
        value = Regex.Replace(value, @"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[地址]");
        value = Regex.Replace(value, @"([A-Za-z]:\\Users\\)[^\\\r\n|]+", "$1[用户]", RegexOptions.IgnoreCase);
        value = value.Trim();
        return value.Length > 600 ? value[..600] + "…" : value;
    }

    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) =>
        ApplyAsync(ips, program, hy2Port, 443, auth);
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) =>
        UpdateNodeAsync(ips, program, hy2Port, 443);
    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null) =>
        ExecuteAsync(KillSwitchPlanner.Plan(ips, KillSwitchPlanner.TunAlias, program, hy2Port, KillSwitchMode.Apply, realityPort, auth),
            () => WfpPlanner.PlanGlobal(ips, program, hy2Port, realityPort, auth), rememberAuth: true, auth: auth, installRoutes: true, phase: "套用");
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        ExecuteAsync(KillSwitchPlanner.UpdateNode(ips, program, hy2Port, realityPort),
            () => WfpPlanner.PlanGlobal(ips, program, hy2Port, realityPort, lastAuth), phase: "换节点");
    public Task RemoveAsync() => ExecuteAsync([new RemoveRulesByPrefix(KillSwitchPlanner.Prefix), new RestoreProfileDefault()], remove: true, phase: "撤销");

    public Task ApplyAppsAsync(IReadOnlyList<string> programs) => ApplyAppsAsync(programs, programs);

    /// <summary>防火墙规则按用户所选程序;过滤层按连带范围内的全部程序文件(filterPrograms)。</summary>
    public Task ApplyAppsAsync(IReadOnlyList<string> programs, IReadOnlyList<string> filterPrograms) =>
        ExecuteAsync(KillSwitchPlanner.PlanApps(programs), () => WfpPlanner.PlanApps(filterPrograms), rememberAuth: true, phase: "套用指定程序");
    public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules) => PatrolAsync(expectedRules, true);

    public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock)
        => PatrolAsync(expectedRules, enforceDefaultBlock, CancellationToken.None);

    public async Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock, CancellationToken token)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var wfpFailed = false;
            var wfpRebuilt = false;
            if (wfp is not null && !File.Exists(wfpOffPath) && wfpPolicy is not null)
            {
                try
                {
                    var names = wfp.ListFilterNames();
                    if (names.Count != wfpPolicy.Count || !names.Order(StringComparer.Ordinal)
                        .SequenceEqual(wfpPolicy.Select(filter => filter.Name).Order(StringComparer.Ordinal), StringComparer.Ordinal))
                    {
                        wfp.Install(wfpPolicy);
                        wfpRebuilt = true;
                    }
                }
                catch (WfpException) { wfpFailed = true; }
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(ScriptTimeout);
            var started = Stopwatch.GetTimestamp();
            var script = KillSwitchPlanner.ToPowerShellScript([new Patrol(expectedRules.ToArray(), EnforceDefaultBlock: enforceDefaultBlock)], StatePath, AuditPath);
            CommandResult result;
            try { result = await runner.RunAsync(CreateStartInfo(script), timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // 只有本类计时器到点才算超时；外部令牌取消照旧让取消异常透出。
                WriteLog(FormatTimeoutLog("巡检", started));
                throw new TimeoutException(ScriptTimedOut);
            }
            // 巡检每 60 秒一次，正常且很快结束的运行不写记录。
            if (result.ExitCode != 0 || ElapsedMilliseconds(started) >= 30000) WriteLog(FormatResultLog("巡检", result, started));
            if (result.ExitCode == VerifyFailedExitCode)
                throw new FirewallIneffectiveException("系统防火墙已被关闭或被策略覆盖，断网保护无法生效，已拒绝连接。请点击断开，在 Windows 安全中心开启防火墙（或联系管理员解除策略）后重新连接。");
            if (result.ExitCode != 0) throw new InvalidOperationException("断网保护巡检失败,请联系管理员。");
            PatrolReport report;
            try
            {
                var line = result.Output.Split('\n').LastOrDefault(value => !string.IsNullOrWhiteSpace(value));
                using var json = JsonDocument.Parse(line ?? "");
                report = new(ReadNames(json.RootElement, "reenforced"), ReadNames(json.RootElement, "newly_disabled"),
                    ReadNames(json.RootElement, "missing_rules"));
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException)
            { throw new InvalidOperationException("断网保护巡检失败,请联系管理员。"); }
            var routeFailed = false;
            var routeRebuilt = false;
            if (routesApplied && routes is not null && !File.Exists(routeOffPath))
            {
                try
                {
                    if (!await routes.IsInstalledAsync(token).ConfigureAwait(false))
                    {
                        await routes.InstallAsync(token).ConfigureAwait(false);
                        routeRebuilt = true;
                    }
                }
                catch (RouteGuardException) { routeFailed = true; }
            }
            if (wfpFailed) throw new WfpUnavailableException(WfpPatrolFailed);
            if (routeFailed) throw new RouteGuardUnavailableException(RoutePatrolFailed);
            if (wfpRebuilt) report = report with { MissingRules = [.. report.MissingRules, WfpPlanner.MissingMarker] };
            if (routeRebuilt) report = report with { MissingRules = [.. report.MissingRules, RouteGuard.MissingMarker] };
            return report;
        }
        finally { gate.Release(); }
    }

    private static string[] ReadNames(JsonElement value, string name)
        => value.GetProperty(name).EnumerateArray().Select(item => item.GetString() ?? throw new JsonException()).ToArray();

    // A snapshot with applied=false also needs recovery: the process may have died partway through Apply.
    public async Task<string?> RecoverAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var routesRemoved = true;
            string? warning;
            try
            {
                var wfpFailed = !RemoveWfp();
                warning = await RecoverFirewallAsync().ConfigureAwait(false);
                if (wfpFailed) throw new InvalidOperationException(WfpRemoveFailed);
            }
            finally { routesRemoved = await RemoveRoutesAsync().ConfigureAwait(false); }
            if (!routesRemoved) throw new InvalidOperationException(RouteRemoveFailed);
            return warning;
        }
        finally { gate.Release(); }
    }

    private async Task<string?> RecoverFirewallAsync()
    {
            if (!File.Exists(StatePath)) return LastRecoveryWarning;
            if (await RunRecoveryStageAsync([new RemoveRulesByPrefix(KillSwitchPlanner.Prefix), new RestoreProfileDefault()], "restore").ConfigureAwait(false) == 0)
            {
                LastRecoveryWarning = null;
                return null;
            }
            if (File.Exists(StatePath) && await RunRecoveryStageAsync([new RecoverFallback()], "fallback").ConfigureAwait(false) == 0)
            {
                LastRecoveryWarning = "启动时未能按原记录完整恢复断网保护，已降级恢复网络设置并归档记录；请联系管理员检查恢复记录。";
                return LastRecoveryWarning;
            }
            throw new InvalidOperationException("防火墙操作失败，恢复记录已保留，请联系管理员。");
    }

    private async Task<int> RunRecoveryStageAsync(IReadOnlyList<FirewallAction> actions, string stage)
    {
        var phase = stage == "restore" ? "启动恢复" : "降级恢复";
        var started = Stopwatch.GetTimestamp();
        using var timeout = new CancellationTokenSource();
        timeout.CancelAfter(ScriptTimeout);
        CommandResult result;
        try
        {
            result = await runner.RunAsync(CreateStartInfo(KillSwitchPlanner.ToPowerShellScript(actions, StatePath, AuditPath)), timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // 本阶段超时不抛出，交回 -1 让启动恢复照旧进入降级恢复。
            WriteLog(FormatTimeoutLog(phase, started));
            await AppendRecoveryLineAsync($"{DateTime.UtcNow:O} {stage} timeout").ConfigureAwait(false);
            return -1;
        }
        WriteLog(FormatResultLog(phase, result, started));
        if (result.ExitCode != 0)
            await AppendRecoveryLineAsync($"{DateTime.UtcNow:O} {stage} {result.ExitCode}").ConfigureAwait(false);
        return result.ExitCode;
    }

    public static ProcessStartInfo CreateStartInfo(string script)
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script }) start.ArgumentList.Add(arg);
        return start;
    }

    // 仅在既有 gate 内调用。移除失败不遮蔽先前的防火墙异常。
    private bool RemoveWfp()
    {
        try
        {
            wfp?.Remove();
            if (wfp is not null) WriteLog("过滤层移除：成功");
            wfpPolicy = null;
            lastAuth = null;
            return true;
        }
        catch (WfpException) { WriteLog("过滤层移除：失败"); return false; }
    }

    private bool InstallWfp(Func<IReadOnlyList<WfpFilterSpec>> createPolicy, bool rememberAuth, AuthEndpoint? auth)
    {
        if (wfp is null) return true;
        var policy = createPolicy(); // 参数错误不能被吞掉，也不能执行脚本。
        if (rememberAuth) lastAuth = auth;
        if (File.Exists(wfpOffPath))
        {
            try { wfp.Remove(); wfpPolicy = null; }
            catch (WfpException) { /* 显式关闭时清理旧过滤器，但不报告 WFP 安装错误。 */ }
            return true;
        }
        try
        {
            wfp.Install(policy);
            wfpPolicy = policy;
            WriteLog("过滤层安装：成功");
            return true;
        }
        catch (WfpException) { WriteLog("过滤层安装：失败"); return false; }
    }

    private async Task ExecuteAsync(IReadOnlyList<FirewallAction> actions,
        Func<IReadOnlyList<WfpFilterSpec>>? createPolicy = null, bool rememberAuth = false, AuthEndpoint? auth = null,
        bool remove = false, bool installRoutes = false, string phase = "")
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var installed = createPolicy is null || InstallWfp(createPolicy, rememberAuth, auth);
            var removed = true;
            var routesRemoved = true;
            try { await RunActionsAsync(actions, phase).ConfigureAwait(false); }
            finally
            {
                if (remove)
                {
                    try { removed = RemoveWfp(); }
                    finally { routesRemoved = await RemoveRoutesAsync().ConfigureAwait(false); }
                }
            }
            if (!removed) throw new InvalidOperationException(WfpRemoveFailed);
            if (!routesRemoved) throw new InvalidOperationException(RouteRemoveFailed);
            if (!installed) throw new WfpUnavailableException(WfpConnectRefused);
            if (installRoutes && routes is not null)
            {
                if (File.Exists(routeOffPath)) await RemoveRoutesAsync().ConfigureAwait(false);
                else
                {
                    try { await routes.InstallAsync(CancellationToken.None).ConfigureAwait(false); routesApplied = true; }
                    catch (RouteGuardException) { throw new RouteGuardUnavailableException(RouteConnectRefused); }
                }
            }
        }
        finally { gate.Release(); }
    }

    // 撤销尽力执行，失败不遮蔽更早的防火墙或过滤层异常。
    private async Task<bool> RemoveRoutesAsync()
    {
        try
        {
            if (routes is not null) await routes.RemoveAsync(CancellationToken.None).ConfigureAwait(false);
            routesApplied = false;
            return true;
        }
        catch (Exception) { return false; }
    }

    private async Task RunActionsAsync(IReadOnlyList<FirewallAction> actions, string phase)
    {
            var started = Stopwatch.GetTimestamp();
            using var timeout = new CancellationTokenSource();
            timeout.CancelAfter(ScriptTimeout);
            CommandResult result;
            try
            {
                result = await runner.RunAsync(CreateStartInfo(KillSwitchPlanner.ToPowerShellScript(actions, StatePath, AuditPath)), timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // 本类计时器到点：撤销时 finally 里的过滤层与兜底路由移除照旧执行。
                WriteLog(FormatTimeoutLog(phase, started));
                throw new TimeoutException(ScriptTimedOut);
            }
            WriteLog(FormatResultLog(phase, result, started));
            if (result.ExitCode == VerifyFailedExitCode && actions.Any(action => action is VerifyRules))
                throw new FirewallIneffectiveException("系统防火墙未运行、未开启或指定程序的阻断规则未生效,已拒绝连接。请在 Windows 安全中心开启防火墙或联系管理员。");
            if (result.ExitCode == VerifyFailedExitCode)
                throw new FirewallIneffectiveException("系统防火墙已被关闭或被策略覆盖，断网保护无法生效，已拒绝连接。请点击断开，在 Windows 安全中心开启防火墙（或联系管理员解除策略）后重新连接。");
            if (result.ExitCode != 0) throw new InvalidOperationException("防火墙操作失败，恢复记录已保留，请联系管理员。");
    }
}
