using System.Diagnostics;
using System.Net;

namespace WinClient.Core.Firewall;

public interface IKillSwitch
{
    Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port);
    Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port);
    Task RemoveAsync();
    Task<string?> RecoverAsync();
    Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        realityPort == 443 ? ApplyAsync(ips, program, hy2Port) : throw new InvalidOperationException("当前断网保护不支持此出口端口。");
    Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        realityPort == 443 ? UpdateNodeAsync(ips, program, hy2Port) : throw new InvalidOperationException("当前断网保护不支持此出口端口。");
}

public sealed class FirewallIneffectiveException(string message) : InvalidOperationException(message);

public sealed class KillSwitchApplier : IKillSwitch
{
    public const int VerifyFailedExitCode = 3;
    private readonly ICommandRunner runner;
    private readonly SemaphoreSlim gate = new(1, 1);
    public string StatePath { get; }
    public string AuditPath { get; }
    public string? LastRecoveryWarning { get; private set; }
    public KillSwitchApplier(string runDirectory, ICommandRunner? runner = null)
    {
        this.runner = runner ?? new CommandRunner();
        StatePath = Path.Combine(runDirectory, "killswitch-state.json");
        AuditPath = Path.Combine(runDirectory, "firewall-audit.json");
    }

    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) =>
        ExecuteAsync(KillSwitchPlanner.Plan(ips, KillSwitchPlanner.TunAlias, program, hy2Port, KillSwitchMode.Apply));
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) =>
        ExecuteAsync(KillSwitchPlanner.UpdateNode(ips, program, hy2Port));
    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        ExecuteAsync(KillSwitchPlanner.Plan(ips, KillSwitchPlanner.TunAlias, program, hy2Port, KillSwitchMode.Apply, realityPort));
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) =>
        ExecuteAsync(KillSwitchPlanner.UpdateNode(ips, program, hy2Port, realityPort));
    public Task RemoveAsync() => ExecuteAsync([new RemoveRulesByPrefix(KillSwitchPlanner.Prefix), new RestoreProfileDefault()]);
    // A snapshot with applied=false also needs recovery: the process may have died partway through Apply.
    public async Task<string?> RecoverAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
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
        finally { gate.Release(); }
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

    private async Task ExecuteAsync(IReadOnlyList<FirewallAction> actions)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(180));
            var result = await runner.RunAsync(CreateStartInfo(KillSwitchPlanner.ToPowerShellScript(actions, StatePath, AuditPath)), timeout.Token).ConfigureAwait(false);
            if (result.ExitCode == VerifyFailedExitCode)
                throw new FirewallIneffectiveException("系统防火墙已被关闭或被策略覆盖，断网保护无法生效，已拒绝连接。请点击断开，在 Windows 安全中心开启防火墙（或联系管理员解除策略）后重新连接。");
            if (result.ExitCode != 0) throw new InvalidOperationException("防火墙操作失败，恢复记录已保留，请联系管理员。");
        }
        finally { gate.Release(); }
    }
}
