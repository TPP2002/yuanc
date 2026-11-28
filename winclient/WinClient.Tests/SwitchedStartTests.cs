using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

public sealed class SwitchedStartTests
{
    private const string Version = "0.2.0";

    // 假时钟：等待只把钟往前拨，不真的等。
    private sealed class Clock
    {
        public DateTimeOffset Now = DateTimeOffset.UnixEpoch;

        public Task Delay(TimeSpan span, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Now += span;
            return Task.CompletedTask;
        }
    }

    private static ControlResponse Reply(string version) =>
        new(1, true, Snapshot: new ControlSnapshot(ConnectionState.Disconnected, "", "", false) { ServiceVersion = version });

    [Fact]
    public async Task HealthyOnceStatusReportsExpectedVersion()
    {
        var clock = new Clock();
        var calls = 0;
        var healthy = await SwitchedStart.WaitHealthyAsync(
            _ => Task.FromResult<ControlResponse?>(++calls < 3 ? null : Reply(Version)), Version, () => clock.Now, clock.Delay);
        Assert.True(healthy);
        Assert.Equal(3, calls);
        Assert.True(clock.Now - DateTimeOffset.UnixEpoch < SwitchedStart.HealthBudget);
    }

    [Fact]
    public async Task OtherVersionIsNotHealthy()
    {
        var clock = new Clock();
        var calls = 0;
        var healthy = await SwitchedStart.WaitHealthyAsync(
            _ => { calls++; return Task.FromResult<ControlResponse?>(Reply("0.1.0")); }, Version, () => clock.Now, clock.Delay);
        Assert.False(healthy);
        Assert.True(clock.Now - DateTimeOffset.UnixEpoch >= SwitchedStart.HealthBudget);
        Assert.True(calls >= 2);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("not-ok")]
    [InlineData("no-snapshot")]
    public async Task FailedResponsesAreNotHealthy(string kind)
    {
        var clock = new Clock();
        ControlResponse? response = kind switch
        {
            "null" => null,
            "not-ok" => Reply(Version) with { Ok = false },
            _ => new ControlResponse(1, true),
        };
        var healthy = await SwitchedStart.WaitHealthyAsync(_ => Task.FromResult(response), Version, () => clock.Now, clock.Delay);
        Assert.False(healthy);
        Assert.True(clock.Now - DateTimeOffset.UnixEpoch >= SwitchedStart.HealthBudget);
    }

    [Fact]
    public async Task ProbeTimeoutCountsAsNoResponse()
    {
        var clock = new Clock();
        var calls = 0;
        var healthy = await SwitchedStart.WaitHealthyAsync(_ =>
        {
            if (++calls == 1) throw new OperationCanceledException();
            return Task.FromResult<ControlResponse?>(Reply(Version));
        }, Version, () => clock.Now, clock.Delay);
        Assert.True(healthy);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task OuterCancellationStopsWaiting()
    {
        var clock = new Clock();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SwitchedStart.WaitHealthyAsync(
            _ => Task.FromResult<ControlResponse?>(null), Version, () => clock.Now, clock.Delay, cancelled.Token));
    }

    [Theory]
    [InlineData(false, false, SwitchedStart.NoPreviousMessage)]
    [InlineData(false, true, SwitchedStart.NoPreviousMessage)]
    [InlineData(true, true, SwitchedStart.RolledBackMessage)]
    [InlineData(true, false, SwitchedStart.RollbackNotRunningMessage)]
    public void FailureMessageSaysWhatHappened(bool available, bool running, string expected)
    {
        Assert.Equal(expected, SwitchedStart.FailureMessage(available, running));
    }

    [Fact]
    public void MessagesAreTheAgreedTexts()
    {
        Assert.Equal("新版本的后台服务未能启动，已改回原来的版本。", SwitchedStart.RolledBackMessage);
        Assert.Equal("新版本的后台服务未能启动，原来的版本已经不在，没有改回。请重新安装，或联系管理员。", SwitchedStart.NoPreviousMessage);
        Assert.Equal("新版本的后台服务未能启动，已改回原来的版本，但原来的后台服务也没能启动。请重启电脑，或联系管理员。", SwitchedStart.RollbackNotRunningMessage);
        Assert.Equal(TimeSpan.FromSeconds(60), SwitchedStart.HealthBudget);
        Assert.Equal(TimeSpan.FromSeconds(2), SwitchedStart.ProbeInterval);
    }
}
