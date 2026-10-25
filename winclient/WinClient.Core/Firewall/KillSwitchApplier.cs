using System.Diagnostics;
using System.Net;
using System.Text.Json;

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

public sealed class KillSwitchApplier : IKillSwitch
{
    public const int VerifyFailedExitCode = 3;
    public const string WfpConnectRefused = "系统过滤层断网保护未能建立,已拒绝连接。请点击断开后重试,仍失败请联系管理员。";
    public const string WfpRemoveFailed = "系统过滤层断网保护未能撤销,网络可能仍被阻断;请重试断开或联系管理员。";
    public const string WfpPatrolFailed = "系统过滤层过滤器缺失且未能重建,断网保护可能失效,请联系管理员";
    private readonly ICommandRunner runner;
    private readonly IWfpEngine? wfp;
    private readonly string wfpOffPath;
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
    public KillSwitchApplier(string runDirectory, ICommandRunner? runner = null, IWfpEngine? wfp = null)
    {
        this.runner = runner ?? new CommandRunner();
        this.wfp = wfp;
        wfpOffPath = Path.Combine(runDirectory, "wfp-off");
        StatePath = Path.Combine(runDirectory, "killswitch-state.json");
        AuditPath = Path.Combine(runDirectory, "firewall-audit.json");
    }

    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) =>
        ApplyAsync(ips, program, hy2Port, 443, auth);
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) =>
        UpdateNodeAsync(ips, program, hy2Port, 443);
    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null) =>
        ExecuteAsync(KillSwitchPlanner.Plan(ips, KillSwitchPlanner.TunAlias, program, hy2Port, KillSwitchMode.Apply, realityPort, auth),
            () => WfpPlanner.PlanGlobal(ips, program, hy2Port, realityPort, auth), rememberAuth: true, auth: auth);
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        ExecuteAsync(KillSwitchPlanner.UpdateNode(ips, program, hy2Port, realityPort),
            () => WfpPlanner.PlanGlobal(ips, program, hy2Port, realityPort, lastAuth));
    public Task RemoveAsync() => ExecuteAsync([new RemoveRulesByPrefix(KillSwitchPlanner.Prefix), new RestoreProfileDefault()], remove: true);

    public Task ApplyAppsAsync(IReadOnlyList<string> programs) => ApplyAppsAsync(programs, programs);

    /// <summary>防火墙规则按用户所选程序;过滤层按连带范围内的全部程序文件(filterPrograms)。</summary>
    public Task ApplyAppsAsync(IReadOnlyList<string> programs, IReadOnlyList<string> filterPrograms) =>
        ExecuteAsync(KillSwitchPlanner.PlanApps(programs), () => WfpPlanner.PlanApps(filterPrograms), rememberAuth: true);
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
            timeout.CancelAfter(TimeSpan.FromSeconds(180));
            var script = KillSwitchPlanner.ToPowerShellScript([new Patrol(expectedRules.ToArray(), EnforceDefaultBlock: enforceDefaultBlock)], StatePath, AuditPath);
            var result = await runner.RunAsync(CreateStartInfo(script), timeout.Token).ConfigureAwait(false);
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
            if (wfpFailed) throw new WfpUnavailableException(WfpPatrolFailed);
            return wfpRebuilt ? report with { MissingRules = [.. report.MissingRules, WfpPlanner.MissingMarker] } : report;
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
            var wfpFailed = !RemoveWfp();
            var warning = await RecoverFirewallAsync().ConfigureAwait(false);
            if (wfpFailed) throw new InvalidOperationException(WfpRemoveFailed);
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
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(180));
        var result = await runner.RunAsync(CreateStartInfo(KillSwitchPlanner.ToPowerShellScript(actions, StatePath, AuditPath)), timeout.Token).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            try
            {
                // CommandResult 不携带 stderr，不把标准输出中的私有内容写入日志。
                var path = Path.Combine(Path.GetDirectoryName(StatePath)!, "killswitch-recovery.log");
                await File.AppendAllTextAsync(path, $"{DateTime.UtcNow:O} {stage} {result.ExitCode}{Environment.NewLine}").ConfigureAwait(false);
            }
            catch (Exception) { /* 追加证据失败不能阻断恢复。 */ }
        }
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
            wfpPolicy = null;
            lastAuth = null;
            return true;
        }
        catch (WfpException) { return false; }
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
        try { wfp.Install(policy); wfpPolicy = policy; return true; }
        catch (WfpException) { return false; }
    }

    private async Task ExecuteAsync(IReadOnlyList<FirewallAction> actions,
        Func<IReadOnlyList<WfpFilterSpec>>? createPolicy = null, bool rememberAuth = false, AuthEndpoint? auth = null, bool remove = false)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var installed = createPolicy is null || InstallWfp(createPolicy, rememberAuth, auth);
            var removed = true;
            try { await RunActionsAsync(actions).ConfigureAwait(false); }
            finally { if (remove) removed = RemoveWfp(); }
            if (!removed) throw new InvalidOperationException(WfpRemoveFailed);
            if (!installed) throw new WfpUnavailableException(WfpConnectRefused);
        }
        finally { gate.Release(); }
    }

    private async Task RunActionsAsync(IReadOnlyList<FirewallAction> actions)
    {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(180));
            var result = await runner.RunAsync(CreateStartInfo(KillSwitchPlanner.ToPowerShellScript(actions, StatePath, AuditPath)), timeout.Token).ConfigureAwait(false);
            if (result.ExitCode == VerifyFailedExitCode && actions.Any(action => action is VerifyRules))
                throw new FirewallIneffectiveException("系统防火墙未运行、未开启或指定程序的阻断规则未生效,已拒绝连接。请在 Windows 安全中心开启防火墙或联系管理员。");
            if (result.ExitCode == VerifyFailedExitCode)
                throw new FirewallIneffectiveException("系统防火墙已被关闭或被策略覆盖，断网保护无法生效，已拒绝连接。请点击断开，在 Windows 安全中心开启防火墙（或联系管理员解除策略）后重新连接。");
            if (result.ExitCode != 0) throw new InvalidOperationException("防火墙操作失败，恢复记录已保留，请联系管理员。");
    }
}
