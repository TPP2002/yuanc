using System.Net;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Pairing;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

/// <summary>首次连接失败自动恢复与测试包自动断开的控制器用例;替身只记录调用,不碰真系统。</summary>
public sealed class ConnectAbandonTests
{
    private const string Restored = "连接失败，已恢复原来的网络，当前没有走澳洲出口。";
    private const string NotRestored = "连接失败，原来的网络没能恢复：请点「断开」再试一次，还不行就重启电脑。";

    private sealed class TestFirewall(List<string> order) : IKillSwitch
    {
        public bool HasPendingState { get; set; }
        public string? PendingMode { get; set; }
        public Exception? ApplyError { get; set; }
        public Exception? RemoveError { get; set; }
        public TaskCompletionSource? ApplyGate { get; init; }
        public TaskCompletionSource ApplyEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private async Task ApplyCore()
        {
            order.Add("apply");
            ApplyEntered.TrySetResult();
            if (ApplyGate is { } gate) await gate.Task;
            if (ApplyError is not null) throw ApplyError;
        }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) => ApplyCore();
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null) => ApplyCore();
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) { order.Add("update"); return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) { order.Add("update"); return Task.CompletedTask; }
        public Task RemoveAsync() { order.Add("remove"); if (RemoveError is not null) throw RemoveError; return Task.CompletedTask; }
        public Task<string?> RecoverAsync() { order.Add("recover"); return Task.FromResult<string?>(null); }
    }

    private sealed class TestTunnel(List<string> order) : ITunnelTransport
    {
        public bool FailStart { get; set; }
        public Exception? StartError { get; set; }
        public JsonElement Config { get; private set; }
        public event EventHandler? TunnelDown;
        public void Drop() => TunnelDown?.Invoke(this, EventArgs.Empty);
        public Task StartAsync(JsonElement configuration, CancellationToken token)
        {
            Config = configuration;
            order.Add("start");
            return StartError is not null ? Task.FromException(StartError)
                : FailStart ? Task.FromException(new IOException("测试断线")) : Task.CompletedTask;
        }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }

    private sealed class QueueSource : ISessionSource
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<AuthResponse<SessionResponse>> queue = new();
        public string Mode => "邀请码模式";
        public void Enqueue(AuthResponse<SessionResponse> response) => queue.Enqueue(response);
        public Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken token = default) =>
            Task.FromResult(queue.TryDequeue(out var next) ? next : throw new InvalidOperationException("测试脚本没有预设下一次会话结果。"));
    }

    private sealed class TestTimers
    {
        private readonly List<(TimeSpan Delay, TaskCompletionSource Completion, string Purpose)> entries = [];
        private readonly Dictionary<string, System.Threading.Channels.Channel<(TimeSpan, TaskCompletionSource)>> queues = new();
        public int Published;
        public Task Delay(TimeSpan delay, CancellationToken token) => Delay(delay, token, "");
        public Task Delay(TimeSpan delay, CancellationToken token, string purpose)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            token.Register(() => completion.TrySetCanceled(token));
            lock (entries)
            {
                entries.Add((delay, completion, purpose));
                QueueFor(purpose).Writer.TryWrite((delay, completion));
            }
            return completion.Task;
        }
        private System.Threading.Channels.Channel<(TimeSpan, TaskCompletionSource)> QueueFor(string purpose)
        {
            if (!queues.TryGetValue(purpose, out var queue))
                queues[purpose] = queue = System.Threading.Channels.Channel.CreateUnbounded<(TimeSpan, TaskCompletionSource)>();
            return queue;
        }
        public ValueTask<(TimeSpan Delay, TaskCompletionSource Completion)> TakeAsync(string purpose, CancellationToken token)
        { lock (entries) return QueueFor(purpose).Reader.ReadAsync(token); }
        public TimeSpan[] For(params string[] purposes)
        { lock (entries) return entries.Where(e => purposes.Contains(e.Purpose)).Select(e => e.Delay).ToArray(); }
        public void Fire(string purpose, Func<TimeSpan, bool> match)
        {
            TaskCompletionSource target;
            lock (entries)
                target = entries.First(e => !e.Completion.Task.IsCompleted && e.Purpose == purpose && match(e.Delay)).Completion;
            target.SetResult();
        }
    }

    private sealed class NullProbe : IExitProbe
    {
        public Task<IPAddress?> ProbeAsync(CancellationToken token) => Task.FromResult<IPAddress?>(null);
    }

    private sealed class NodeProbe : IExitProbe
    {
        public Task<IPAddress?> ProbeAsync(CancellationToken token) => Task.FromResult<IPAddress?>(IPAddress.Parse(TestData.Node().Host));
    }

    private static AuthResponse<SessionResponse> Ok(SessionResponse value) => new(AuthResult.Ok, value);

    private static async Task Until(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("等待控制器处理超时。");
            await Task.Delay(10);
        }
    }

    private static async Task FireAndSettle(ClientController controller, TestTimers timers, string purpose, TimeSpan duration)
    {
        var published = Volatile.Read(ref timers.Published);
        timers.Fire(purpose, d => d == duration);
        await Until(() => Volatile.Read(ref timers.Published) > published || controller.Snapshot.State == ConnectionState.Disconnected);
        await Task.Delay(20);
    }

    [Fact]
    public async Task FirstConnectTunnelRetriesStopAfterThreeBackoffsAndRestoreNetwork()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var tunnel = new TestTunnel(order) { FailStart = true };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8 })
        {
            var scheduled = await timers.TakeAsync("退避", timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            scheduled.Completion.SetResult();
            await Task.Delay(20);
        }
        await Until(() => controller.Snapshot.State == ConnectionState.Disconnected);
        await controller.RefreshSessionAsync(); // 串行锁屏障:状态先变,提示语晚一步写,等放弃并恢复整段做完再读。
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(Restored + "原因：连续 4 次都没连上澳洲出口。", controller.Snapshot.Message);
        Assert.Equal(4, order.Count(x => x == "start"));
        Assert.Equal(1, order.Count(x => x == "remove"));
        Assert.True(order.LastIndexOf("remove") > order.LastIndexOf("start"));
        Assert.Equal(3, timers.For("退避").Length);
    }

    [Fact]
    public async Task FirstConnectAuthNetworkRetriesStopWithoutTouchingFirewall()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var source = new QueueSource();
        for (var i = 0; i < 4; i++) source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.Network));
        using var controller = new ClientController(source, new TestFirewall(order), new TestTunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8 })
        {
            var scheduled = await timers.TakeAsync("退避", timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            scheduled.Completion.SetResult();
            await Task.Delay(20);
        }
        await Until(() => controller.Snapshot.State == ConnectionState.Disconnected);
        await controller.RefreshSessionAsync(); // 串行锁屏障:等放弃并恢复整段做完再读提示语。
        Assert.Equal(Restored + "原因：连续 4 次都没连上澳洲出口。", controller.Snapshot.Message);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task FirstConnectMissingKernelRestoresNetworkAndKeepsRestoreMessage()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var tunnel = new TestTunnel(order) { StartError = new FileNotFoundException("缺少内核") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(Restored + "原因：未找到连接内核。", controller.Snapshot.Message);
        Assert.Contains("remove", order);
    }

    [Fact]
    public async Task HeldProtectionMissingKernelStillNeedsManualWithOriginalMessage()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var tunnel = new TestTunnel(order) { StartError = new FileNotFoundException("缺少内核") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order) { HasPendingState = true }, tunnel, Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("未找到连接内核，请联系管理员配置 sing-box.exe 路径。", controller.Snapshot.Message);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task FirstConnectApplyTimeoutRestoresNetworkAndNamesTimeout()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var firewall = new TestFirewall(order) { ApplyError = new TimeoutException("超时") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(Restored + "原因：有一步操作超过时限没有完成。", controller.Snapshot.Message);
        Assert.Contains("remove", order);
    }

    [Fact]
    public async Task FirstConnectRestoreFailureNeedsManualKeepsProtectionAndTellsHowToRecover()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var firewall = new TestFirewall(order)
        {
            ApplyError = new WfpUnavailableException("测试过滤层失败"),
            RemoveError = new InvalidOperationException("测试撤销失败")
        };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(NotRestored + "原因：系统过滤层的保护没能建立。", controller.Snapshot.Message);
    }

    [Fact]
    public async Task FirstConnectSessionExpiredAfterApplyDropsProtectionButKeepsNeedsLogin()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var source = new QueueSource();
        source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromSeconds(1))));
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firewall = new TestFirewall(order) { ApplyGate = gate };
        using var controller = new ClientController(source, firewall, new TestTunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        var running = controller.ConnectAsync();
        await firewall.ApplyEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(1200);
        gate.SetResult();
        await running.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ConnectionState.NeedsLogin, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal("登录已到期，请重新登录。 已恢复原来的网络。", controller.Snapshot.Message);
        Assert.Contains("remove", order);
        Assert.DoesNotContain("start", order);
    }

    [Fact]
    public async Task ReconnectAfterConnectedStillRetriesBeyondThreeBackoffs()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var tunnel = new TestTunnel(order);
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        tunnel.FailStart = true;
        tunnel.Drop();
        await Until(() => timers.For("").Length >= 1);
        timers.Fire("", d => d == TimeSpan.Zero);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8, 16 })
        {
            var scheduled = await timers.TakeAsync("退避", timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            Assert.True(controller.Snapshot.ProtectionActive);
            scheduled.Completion.SetResult();
            await Task.Delay(20);
        }
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task DisconnectDuringFirstAttemptUsesNormalDisconnectPath()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var abandoned = 0;
        var tunnel = new TestTunnel(order) { FailStart = true };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.AttemptAbandoned += () => Interlocked.Increment(ref abandoned);
        await controller.ConnectAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        _ = await timers.TakeAsync("退避", timeout.Token);
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.Equal("已断开，原网络设置已恢复。", controller.Snapshot.Message);
        Assert.Equal(1, order.Count(x => x == "remove"));
        Assert.Equal(0, Volatile.Read(ref abandoned));
    }

    [Fact]
    public async Task AbandonRaisesEventOnceAndWritesJournal()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var abandoned = 0;
        using (var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order) { ApplyError = new FirewallIneffectiveException("测试防火墙失败") },
            new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = line => journal.Enqueue(line) })
        {
            controller.AttemptAbandoned += () => Interlocked.Increment(ref abandoned);
            await controller.ConnectAsync();
            Assert.Equal(1, Volatile.Read(ref abandoned));
            var lines = journal.ToArray();
            Assert.Contains(lines, line => line.StartsWith("连接失败：", StringComparison.Ordinal));
            Assert.Contains("放弃并恢复：系统防火墙没生效，撤销=成功", lines);
            Assert.DoesNotContain("192.0.2.5", string.Join("\n", lines));
        }
        var secondOrder = new List<string>();
        var secondTimers = new TestTimers();
        using (var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(secondOrder) { ApplyError = new FirewallIneffectiveException("测试防火墙失败") },
            new TestTunnel(secondOrder), Path.GetFullPath("fake.exe"), TestData.Device, secondTimers.Delay)
            { DelayWithPurposeAsync = secondTimers.Delay, Journal = _ => throw new InvalidOperationException("记录订阅者抛错") })
        {
            controller.AttemptAbandoned += () => throw new InvalidOperationException("事件订阅者抛错");
            await controller.ConnectAsync();
            Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
            Assert.Contains("remove", secondOrder);
        }
    }

    [Fact]
    public async Task TestBuildDisconnectsAndRestoresWhenExitCannotBeVerified()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var abandoned = 0;
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay,
            exitProbe: new NullProbe())
            { DelayWithPurposeAsync = timers.Delay, TestBuild = true, Journal = line => journal.Enqueue(line) };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        controller.AttemptAbandoned += () => Interlocked.Increment(ref abandoned);
        await controller.ConnectAsync();
        await FireAndSettle(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        for (var attempt = 1; attempt < 5; attempt++)
            await FireAndSettle(controller, timers, "出口核验", TimeSpan.FromSeconds(5));
        await Until(() => controller.Snapshot.State == ConnectionState.Disconnected);
        await controller.RefreshSessionAsync(); // 串行锁屏障:等放弃并恢复整段做完再读提示语。
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal("测试包：出口核验不了，已自动断开并恢复原来的网络。", controller.Snapshot.Message);
        Assert.True(order.IndexOf("stop") < order.IndexOf("remove"));
        Assert.Equal(1, Volatile.Read(ref abandoned));
        Assert.Contains("放弃并恢复：测试包出口核验不了，撤销=成功", journal.ToArray());
        Assert.DoesNotContain(TimeSpan.FromMinutes(1), timers.For("出口核验"));
    }

    [Fact]
    public async Task TestBuildRechecksExitEveryMinute()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay,
            exitProbe: new NodeProbe())
            { DelayWithPurposeAsync = timers.Delay, TestBuild = true };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndSettle(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Contains(TimeSpan.FromMinutes(1), timers.For("出口核验"));

        var order2 = new List<string>();
        var timers2 = new TestTimers();
        using var normal = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order2), new TestTunnel(order2), Path.GetFullPath("fake.exe"), TestData.Device, timers2.Delay,
            exitProbe: new NodeProbe())
            { DelayWithPurposeAsync = timers2.Delay };
        normal.Changed += _ => Interlocked.Increment(ref timers2.Published);
        await normal.ConnectAsync();
        await FireAndSettle(normal, timers2, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Contains(TimeSpan.FromMinutes(5), timers2.For("出口核验"));
        Assert.DoesNotContain(TimeSpan.FromMinutes(1), timers2.For("出口核验"));
    }

    // END
}
