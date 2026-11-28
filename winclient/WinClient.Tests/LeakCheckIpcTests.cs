using System.IO;
using WinClient.Core.Client;
using WinClient.Core.Diagnostics;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

public sealed class LeakCheckIpcTests
{
    [Fact]
    public async Task LeakCheckReturnsTextFromChecker()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var checker = new FakeChecker();
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path), leakCheck: checker);
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("leak_check", cancellationToken: stop.Token);
            Assert.True(response.Ok);
            Assert.Equal("未发现可疑流量。", response.LeakCheck);
            Assert.Equal(1, Volatile.Read(ref checker.Calls));
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task LeakCheckIsTrustedOnly()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var checker = new FakeChecker();
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path), leakCheck: checker);
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token, callerTrusted: false);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("leak_check", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal(ControlServer.UntrustedCallerError, response.Error);
            Assert.Equal(0, Volatile.Read(ref checker.Calls));
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task LeakCheckUnsupportedWithoutChecker()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path));
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("leak_check", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal("不支持的指令", response.Error);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task SecondLeakCheckIsRejectedAndCommandsStayFree()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var facade = new FakeFacade();
        var gate = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var checker = new FakeChecker { Gate = gate };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path), leakCheck: checker);
        var (first, firstHost) = IpcTests.DuplexStream.Pair();
        var (second, secondHost) = IpcTests.DuplexStream.Pair();
        var servingFirst = server.ServeAsync(firstHost, stop.Token);
        var servingSecond = server.ServeAsync(secondHost, stop.Token);
        using (var one = new ControlClient(first))
        using (var two = new ControlClient(second))
        {
            var running = one.SendAsync("leak_check", cancellationToken: stop.Token);
            await checker.Entered.Task.WaitAsync(stop.Token);
            var busy = await two.SendAsync("leak_check", cancellationToken: stop.Token);
            Assert.False(busy.Ok);
            Assert.Equal(ControlServer.LeakCheckBusyError, busy.Error);
            var connect = await two.SendAsync("connect", cancellationToken: stop.Token);
            Assert.True(connect.Ok);
            Assert.Equal(new[] { "connect" }, facade.Actions);
            Assert.Equal(1, Volatile.Read(ref checker.Calls));
            gate.SetResult("未发现可疑流量。");
            var done = await running;
            Assert.True(done.Ok);
            Assert.Equal("未发现可疑流量。", done.LeakCheck);
        }
        await Task.WhenAll(servingFirst, servingSecond).WaitAsync(stop.Token);
    }

    [Fact]
    public async Task LeakCheckFailureHidesExceptionText()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var checker = new FakeChecker { Error = new IOException(@"C:\secret\capture.etl 被占用") };
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path), leakCheck: checker);
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("leak_check", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal(ControlServer.LeakCheckFailedError, response.Error);
            Assert.DoesNotContain("secret", response.Error);
            var again = await client.SendAsync("leak_check", cancellationToken: stop.Token);
            Assert.Equal(ControlServer.LeakCheckFailedError, again.Error);
            Assert.Equal(2, Volatile.Read(ref checker.Calls));
        }
        await serving.WaitAsync(stop.Token);
    }

    private sealed class FakeFacade : IClientFacade
    {
        public List<string> Actions { get; } = [];
        public ClientSnapshot Snapshot { get; private set; } = new(ConnectionState.Disconnected, "未连接", "", false);
        public event Action<ClientSnapshot>? Changed { add { } remove { } }
        public Task ConnectAsync() { Actions.Add("connect"); Snapshot = new(ConnectionState.Connected, "已连接", "", true); return Task.CompletedTask; }
        public Task DisconnectAsync() { Actions.Add("disconnect"); return Task.CompletedTask; }
        public Task SetRoutingAsync(string mode, IReadOnlyList<string> apps) => Task.CompletedTask;
        public Task SetEnvironmentEnabledAsync(bool enabled) => Task.CompletedTask;
        public Task RestoreEnvironmentAsync() => Task.CompletedTask;
        public Task RedeemAsync(string code) => Task.CompletedTask;
        public Task ImportPairingAsync(string json) => Task.CompletedTask;
        public Task ClearPairingAsync() => Task.CompletedTask;
        public string? ReadAudit() => null;
        public string? ReadSelfCheck() => null;
    }

    private sealed class FakeChecker : ILeakChecker
    {
        public int Calls;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<string>? Gate { get; init; }
        public Exception? Error { get; init; }
        public async Task<string> RunAsync(CancellationToken token)
        {
            Interlocked.Increment(ref Calls);
            Entered.TrySetResult();
            if (Error is not null) throw Error;
            return Gate is null ? "未发现可疑流量。" : await Gate.Task.WaitAsync(token);
        }
    }
}
