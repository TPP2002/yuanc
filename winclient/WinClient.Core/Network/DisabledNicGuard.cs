namespace WinClient.Core.Network;

/// <summary>
/// 测试包用的网卡看护外壳:不检查、不关闭网卡,只把上一版留下的网卡改动按记录恢复。
/// </summary>
public sealed class DisabledNicGuard(INicGuard inner) : INicGuard
{
    public bool HasPendingState => inner.HasPendingState;
    public string? PublicIpv4Adapter() => null;
    public Task ApplyAsync(CancellationToken token) => Task.CompletedTask;
    public Task<NicPatrolReport> PatrolAsync(CancellationToken token) => Task.FromResult(new NicPatrolReport([], []));
    public Task<string?> RestoreAsync() => inner.RestoreAsync();
}
