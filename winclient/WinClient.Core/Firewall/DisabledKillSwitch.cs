using System.Net;

namespace WinClient.Core.Firewall;

/// <summary>
/// 测试包用的断网保护外壳:套用、换节点、巡检一律不执行(也不因出口端口不是 443 抛错),
/// 只有恢复与撤销上一次留下的记录仍转给真执行器。
/// </summary>
public sealed class DisabledKillSwitch(IKillSwitch inner) : IKillSwitch
{
    public bool HasPendingState => inner.HasPendingState;
    public string? PendingMode => inner.PendingMode;
    public string? LastRemoveWarning { get; private set; }

    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) => Task.CompletedTask;
    public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null) => Task.CompletedTask;
    public Task ApplyAppsAsync(IReadOnlyList<string> programs) => Task.CompletedTask;
    public Task ApplyAppsAsync(IReadOnlyList<string> programs, IReadOnlyList<string> filterPrograms) => Task.CompletedTask;
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) => Task.CompletedTask;
    public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) => Task.CompletedTask;
    public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules) => Task.FromResult(PatrolReport.Empty);
    public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock) => Task.FromResult(PatrolReport.Empty);
    public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock, CancellationToken token) => Task.FromResult(PatrolReport.Empty);

    /// <summary>没有恢复记录时不动系统防火墙;有记录(上一版留下的)才撤销。</summary>
    public async Task RemoveAsync()
    {
        LastRemoveWarning = null;
        if (!inner.HasPendingState) return;
        await inner.RemoveAsync();
        LastRemoveWarning = inner.LastRemoveWarning;
    }
    public Task<string?> RecoverAsync() => inner.RecoverAsync();
}
