using System.Net;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

public sealed class DisabledGuardTests
{
    private sealed class RecordingKillSwitch : IKillSwitch
    {
        public bool HasPendingState { get; set; }
        public string? PendingMode { get; set; }
        public int GuardCalls;
        public int RemoveCalls;
        public int RecoverCalls;
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null)
        { GuardCalls++; return Task.CompletedTask; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null)
        { GuardCalls++; return Task.CompletedTask; }
        public Task ApplyAppsAsync(IReadOnlyList<string> programs) { GuardCalls++; return Task.CompletedTask; }
        public Task ApplyAppsAsync(IReadOnlyList<string> programs, IReadOnlyList<string> filterPrograms) { GuardCalls++; return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) { GuardCalls++; return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) { GuardCalls++; return Task.CompletedTask; }
        public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules) { GuardCalls++; return Task.FromResult(PatrolReport.Empty); }
        public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock) { GuardCalls++; return Task.FromResult(PatrolReport.Empty); }
        public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules, bool enforceDefaultBlock, CancellationToken token) { GuardCalls++; return Task.FromResult(PatrolReport.Empty); }
        public Task RemoveAsync() { RemoveCalls++; return Task.CompletedTask; }
        public Task<string?> RecoverAsync() { RecoverCalls++; return Task.FromResult<string?>("恢复提醒"); }
    }

    private sealed class RecordingNicGuard : INicGuard
    {
        public bool HasPendingState { get; set; }
        public int GuardCalls;
        public int RestoreCalls;
        public string? PublicIpv4Adapter() { GuardCalls++; return "拨号连接"; }
        public Task ApplyAsync(CancellationToken token) { GuardCalls++; return Task.CompletedTask; }
        public Task<NicPatrolReport> PatrolAsync(CancellationToken token) { GuardCalls++; return Task.FromResult(new NicPatrolReport(["x"], ["y"])); }
        public Task<string?> RestoreAsync() { RestoreCalls++; return Task.FromResult<string?>("网卡提醒"); }
    }

    [Fact]
    public async Task DisabledKillSwitchNeverAppliesOrPatrolsButStillRecoversAndRemovesLeftovers()
    {
        var inner = new RecordingKillSwitch { HasPendingState = false, PendingMode = "apps" };
        var guard = new DisabledKillSwitch(inner);
        Assert.False(guard.HasPendingState);
        Assert.Equal("apps", guard.PendingMode);
        IPAddress[] ips = [IPAddress.Parse("192.0.2.5")];
        await guard.ApplyAsync(ips, "p.exe", 8443);
        await guard.ApplyAsync(ips, "p.exe", 8443, 443);
        await guard.ApplyAsync(ips, "p.exe", 8443, 8444);
        await guard.ApplyAppsAsync(["p.exe"]);
        await guard.ApplyAppsAsync(["p.exe"], ["p.exe"]);
        await guard.UpdateNodeAsync(ips, "p.exe", 8443);
        await guard.UpdateNodeAsync(ips, "p.exe", 8443, 8444);
        Assert.True((await guard.PatrolAsync(["a"])).Clean);
        Assert.True((await guard.PatrolAsync(["a"], true)).Clean);
        Assert.True((await guard.PatrolAsync(["a"], true, CancellationToken.None)).Clean);
        Assert.Equal(0, inner.GuardCalls);
        Assert.Equal("恢复提醒", await guard.RecoverAsync());
        Assert.Equal(1, inner.RecoverCalls);
        await guard.RemoveAsync();
        Assert.Equal(0, inner.RemoveCalls);
        inner.HasPendingState = true;
        Assert.True(guard.HasPendingState);
        await guard.RemoveAsync();
        Assert.Equal(1, inner.RemoveCalls);
    }

    [Fact]
    public async Task DisabledNicGuardOnlyRestores()
    {
        var inner = new RecordingNicGuard { HasPendingState = true };
        var guard = new DisabledNicGuard(inner);
        Assert.True(guard.HasPendingState);
        Assert.Null(guard.PublicIpv4Adapter());
        await guard.ApplyAsync(CancellationToken.None);
        var patrol = await guard.PatrolAsync(CancellationToken.None);
        Assert.Empty(patrol.NewlyDisabled);
        Assert.Empty(patrol.PublicIpv4Adapters);
        Assert.Equal(0, inner.GuardCalls);
        Assert.Equal("网卡提醒", await guard.RestoreAsync());
        Assert.Equal(1, inner.RestoreCalls);
    }

    [Fact]
    public void GuardForWrapsOnlyInTestBuild()
    {
        var real = new RecordingKillSwitch();
        Assert.Same(real, ClientRuntime.GuardFor(real, false));
        Assert.IsType<DisabledKillSwitch>(ClientRuntime.GuardFor(real, true));
    }
}
