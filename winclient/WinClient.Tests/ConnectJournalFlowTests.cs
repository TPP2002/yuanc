using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Pairing;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

/// <summary>连接过程逐步写进连接记录的控制器用例;替身只记录调用与文字,不碰真系统。</summary>
public sealed class ConnectJournalFlowTests
{
    /// <summary>断网保护替身:记录调用次序,套用与撤销可注入异常,巡检返回预置结果。</summary>
    private sealed class TestFirewall(List<string> order) : IKillSwitch
    {
        public bool HasPendingState { get; set; }
        public string? PendingMode { get; set; }
        public Exception? ApplyError { get; set; }
        public Exception? RemoveError { get; set; }
        public Queue<object> PatrolResults { get; } = new();

        private Task ApplyCore()
        {
            order.Add("apply");
            if (ApplyError is not null) throw ApplyError;
            return Task.CompletedTask;
        }

        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) => ApplyCore();
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null) => ApplyCore();
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) { order.Add("update"); return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort) { order.Add("update"); return Task.CompletedTask; }
        public Task RemoveAsync()
        {
            order.Add("remove");
            if (RemoveError is not null) throw RemoveError;
            return Task.CompletedTask;
        }

        public Task<string?> RecoverAsync() { order.Add("recover"); return Task.FromResult<string?>(null); }

        public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules)
        {
            var next = PatrolResults.Count == 0 ? PatrolReport.Empty : PatrolResults.Dequeue();
            if (next is Exception failure) throw failure;
            return Task.FromResult((PatrolReport)next);
        }
    }

    /// <summary>隧道替身:启动可随时换成抛指定异常。</summary>
    private sealed class TestTunnel(List<string> order) : ITunnelTransport
    {
        public Exception? StartError { get; set; }
        public event EventHandler? TunnelDown;
        public Task StartAsync(JsonElement configuration, CancellationToken token)
        {
            order.Add("start");
            return StartError is null ? Task.CompletedTask : Task.FromException(StartError);
        }
        public void Drop() => TunnelDown?.Invoke(this, EventArgs.Empty);
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }

    /// <summary>会话来源替身:按队列给出鉴权结果,模式按邀请码模式。</summary>
    private sealed class QueueSource : ISessionSource
    {
        private readonly ConcurrentQueue<AuthResponse<SessionResponse>> queue = new();
        public string Mode => "邀请码模式";
        public void Enqueue(AuthResponse<SessionResponse> response) => queue.Enqueue(response);
        public Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken token = default) =>
            Task.FromResult(queue.TryDequeue(out var next) ? next : throw new InvalidOperationException("测试脚本没有预设下一次会话结果。"));
    }

    /// <summary>定时器替身:按用途排队,由用例逐个放行;写法照 ConnectAbandonTests。</summary>
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

    private sealed class NodeProbe : IExitProbe
    {
        public Task<IPAddress?> ProbeAsync(CancellationToken token) => Task.FromResult<IPAddress?>(IPAddress.Parse(TestData.Node().Host));
    }

    private sealed class NullProbe : IExitProbe
    {
        public Task<IPAddress?> ProbeAsync(CancellationToken token) => Task.FromResult<IPAddress?>(null);
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
        await Task.Delay(30);
    }

    private static int IndexOfPrefix(string[] lines, string prefix) =>
        Array.FindIndex(lines, line => line.StartsWith(prefix, StringComparison.Ordinal));

    private static int CountPrefix(string[] lines, string prefix) =>
        lines.Count(line => line.StartsWith(prefix, StringComparison.Ordinal));

    [Fact]
    public void StateAndEffectNamesAreFixed()
    {
        Assert.Equal("未连接", ConnectJournal.StateName(ConnectionState.Disconnected));
        Assert.Equal("连接中", ConnectJournal.StateName(ConnectionState.Connecting));
        Assert.Equal("已连接", ConnectJournal.StateName(ConnectionState.Connected));
        Assert.Equal("重连中", ConnectJournal.StateName(ConnectionState.Reconnecting));
        Assert.Equal("需重新登录", ConnectJournal.StateName(ConnectionState.NeedsLogin));
        Assert.Equal("需人工处理", ConnectJournal.StateName(ConnectionState.NeedsManual));
        Assert.Equal("套用断网保护", ConnectJournal.EffectName(new(EffectKind.ApplyKillSwitch)));
        Assert.Equal("更新节点规则", ConnectJournal.EffectName(new(EffectKind.UpdateKillSwitchNode)));
        Assert.Equal("撤销断网保护", ConnectJournal.EffectName(new(EffectKind.RemoveKillSwitch)));
        Assert.Equal("停止隧道", ConnectJournal.EffectName(new(EffectKind.StopTunnel)));
        Assert.Equal("启动隧道", ConnectJournal.EffectName(new(EffectKind.StartTunnel)));
        Assert.Equal("显示提示", ConnectJournal.EffectName(new(EffectKind.ShowMessage)));
        Assert.Equal("安排退避 8 秒", ConnectJournal.EffectName(new(EffectKind.ScheduleBackoff, TimeSpan.FromSeconds(8))));
    }

    [Fact]
    public void CleanScrubsLikeDescribe()
    {
        Assert.Equal("", ConnectJournal.Clean(null));
        Assert.Equal("a | b [地址] C:\\Users\\[用户]\\x", ConnectJournal.Clean("a\r\nb 203.0.113.9 C:\\Users\\alice\\x"));
        var longText = new string('长', 400);
        Assert.Equal(longText[..300] + "…", ConnectJournal.Clean(longText));
    }

    [Fact]
    public async Task SuccessfulConnectWritesRequestSessionActionsAndStates()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        var lines = journal.ToArray();
        var expected = new[]
        {
            "连接请求：来源=用户，状态=未连接，保护=无，恢复记录=无",
            "开始连接：模式=自用模式，代理范围=全部流量，首次尝试=是",
            "状态：未连接→连接中",
            "取会话：Ok",
            "动作开始：套用断网保护",
            "动作结束：套用断网保护，用时 ",
            "动作开始：启动隧道",
            "状态：连接中→已连接",
            "动作结束：启动隧道，用时 ",
            "连接请求结束：状态=已连接，保护=有",
        };
        var positions = expected.Select(prefix => IndexOfPrefix(lines, prefix)).ToArray();
        Assert.DoesNotContain(-1, positions);
        Assert.Equal(positions.OrderBy(position => position).ToArray(), positions);
    }

    [Fact]
    public async Task RejectedConnectWritesReason()
    {
        var noSourceJournal = new ConcurrentQueue<string>();
        var noSourceOrder = new List<string>();
        var noSourceTimers = new TestTimers();
        using (var controller = new ClientController((ISessionSource?)null, new TestFirewall(noSourceOrder),
            new TestTunnel(noSourceOrder), Path.GetFullPath("fake.exe"), TestData.Device, noSourceTimers.Delay)
            { DelayWithPurposeAsync = noSourceTimers.Delay, Journal = noSourceJournal.Enqueue })
        {
            await controller.ConnectAsync();
        }
        var noSourceLines = noSourceJournal.ToArray();
        Assert.Contains("连接未开始：未配置服务器", noSourceLines);
        Assert.Equal(1, CountPrefix(noSourceLines, "连接请求：来源="));
        Assert.Equal(1, CountPrefix(noSourceLines, "连接请求结束：状态="));

        var busyJournal = new ConcurrentQueue<string>();
        var busyOrder = new List<string>();
        var busyTimers = new TestTimers();
        using (var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(busyOrder), new TestTunnel(busyOrder), Path.GetFullPath("fake.exe"), TestData.Device, busyTimers.Delay)
            { DelayWithPurposeAsync = busyTimers.Delay, Journal = busyJournal.Enqueue })
        {
            await controller.ConnectAsync();
            await controller.ConnectAsync();
        }
        var busyLines = busyJournal.ToArray();
        Assert.Contains("连接未开始：已在连接或已连接", busyLines);
        Assert.Equal(2, CountPrefix(busyLines, "连接请求：来源="));
        Assert.Equal(2, CountPrefix(busyLines, "连接请求结束：状态="));

        var pendingJournal = new ConcurrentQueue<string>();
        var pendingOrder = new List<string>();
        var pendingTimers = new TestTimers();
        using (var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(pendingOrder) { HasPendingState = true, PendingMode = "apps" },
            new TestTunnel(pendingOrder), Path.GetFullPath("fake.exe"), TestData.Device, pendingTimers.Delay)
            { DelayWithPurposeAsync = pendingTimers.Delay, Journal = pendingJournal.Enqueue })
        {
            await controller.ConnectAsync();
        }
        var pendingLines = pendingJournal.ToArray();
        Assert.Contains("连接未开始：恢复记录与代理范围不一致", pendingLines);
        Assert.Equal(1, CountPrefix(pendingLines, "连接请求：来源="));
        Assert.Equal(1, CountPrefix(pendingLines, "连接请求结束：状态="));
    }

    [Fact]
    public async Task TunnelStartFailureWritesReasonAndBackoff()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order) { StartError = new IOException("测试断线") },
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        await controller.ConnectAsync();
        var lines = journal.ToArray();
        Assert.Contains("启动隧道没成功：IOException：测试断线", lines);
        Assert.Contains("动作开始：安排退避 2 秒", lines);
        Assert.Contains("状态：连接中→重连中", lines);
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
    }

    [Fact]
    public async Task SessionResultNameIsWritten()
    {
        var networkJournal = new ConcurrentQueue<string>();
        var networkSource = new QueueSource();
        networkSource.Enqueue(new AuthResponse<SessionResponse>(AuthResult.Network));
        var networkOrder = new List<string>();
        var networkTimers = new TestTimers();
        using (var controller = new ClientController(networkSource, new TestFirewall(networkOrder),
            new TestTunnel(networkOrder), Path.GetFullPath("fake.exe"), TestData.Device, networkTimers.Delay)
            { DelayWithPurposeAsync = networkTimers.Delay, Journal = networkJournal.Enqueue })
        {
            await controller.ConnectAsync();
        }
        Assert.Contains("取会话：Network", networkJournal.ToArray());

        var okJournal = new ConcurrentQueue<string>();
        var okSource = new QueueSource();
        okSource.Enqueue(Ok(TestData.Session()));
        var okOrder = new List<string>();
        var okTimers = new TestTimers();
        using (var controller = new ClientController(okSource, new TestFirewall(okOrder), new TestTunnel(okOrder),
            Path.GetFullPath("fake.exe"), TestData.Device, okTimers.Delay)
            { DelayWithPurposeAsync = okTimers.Delay, Journal = okJournal.Enqueue })
        {
            await controller.ConnectAsync();
        }
        Assert.Contains("取会话：Ok", okJournal.ToArray());
    }

    [Fact]
    public async Task ExitCheckWritesRoundsWithoutAddress()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        var source = new QueueSource();
        source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source,
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay,
            exitProbe: new NodeProbe())
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndSettle(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        await Until(() => journal.Any(line => line == "出口核验：已核验"));
        var verifiedLines = journal.ToArray();
        Assert.Contains("出口核验：已核验", verifiedLines);
        Assert.DoesNotContain(TestData.Node().Host, string.Join("\n", verifiedLines));

        var nullOrder = new List<string>();
        var nullTimers = new TestTimers();
        var nullJournal = new ConcurrentQueue<string>();
        var nullSource = new QueueSource();
        nullSource.Enqueue(Ok(TestData.Session()));
        using var patchy = new ClientController(nullSource,
            new TestFirewall(nullOrder), new TestTunnel(nullOrder), Path.GetFullPath("fake.exe"), TestData.Device, nullTimers.Delay,
            exitProbe: new NullProbe())
            { DelayWithPurposeAsync = nullTimers.Delay, Journal = nullJournal.Enqueue };
        patchy.Changed += _ => Interlocked.Increment(ref nullTimers.Published);
        await patchy.ConnectAsync();
        await FireAndSettle(patchy, nullTimers, "出口核验", TimeSpan.FromSeconds(3));
        await Until(() => nullJournal.Any(line => line.Contains("第 1 次没有回应")));
        for (var attempt = 2; attempt <= 4; attempt++)
        {
            var round = attempt;
            await FireAndSettle(patchy, nullTimers, "出口核验", TimeSpan.FromSeconds(5));
            await Until(() => nullJournal.Any(line => line.Contains($"第 {round} 次没有回应")));
        }
        await FireAndSettle(patchy, nullTimers, "出口核验", TimeSpan.FromSeconds(5));
        await Until(() => nullJournal.Any(line => line.Contains("无法核验，已连续 1 轮")));
        var exits = nullJournal.ToArray();
        Assert.Contains("出口核验：第 1 次没有回应", exits);
        Assert.Contains("出口核验：第 4 次没有回应", exits);
        Assert.Contains("出口核验：无法核验，已连续 1 轮", exits);
        Assert.DoesNotContain(TestData.Node().Host, string.Join("\n", exits));
    }

    [Fact]
    public async Task DisconnectWritesRequestAndResult()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        await controller.ConnectAsync();
        await controller.DisconnectAsync();
        var lines = journal.ToArray();
        Assert.Contains("断开请求：状态=已连接，保护=有", lines);
        Assert.Contains("动作开始：停止隧道", lines);
        Assert.Contains("动作开始：撤销断网保护", lines);
        Assert.Contains("状态：已连接→未连接", lines);
        Assert.Contains("断开完成：环境恢复=成功", lines);
    }

    [Fact]
    public async Task InitializeWritesStartupBranch()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        using (var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue })
        {
            await controller.InitializeAsync(autoConnect: false, keepProtection: false);
        }
        var lines = journal.ToArray();
        Assert.Contains("启动：保持保护=否，自动连接=否，恢复记录=无，模式=自用模式", lines);
        Assert.Contains("启动：已做启动恢复，提醒=无", lines);

        var keptOrder = new List<string>();
        var keptTimers = new TestTimers();
        var keptJournal = new ConcurrentQueue<string>();
        using (var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(keptOrder) { HasPendingState = true }, new TestTunnel(keptOrder),
            Path.GetFullPath("fake.exe"), TestData.Device, keptTimers.Delay)
            { DelayWithPurposeAsync = keptTimers.Delay, Journal = keptJournal.Enqueue })
        {
            await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        }
        Assert.Contains("启动：接回断网保护，随后自动连接", keptJournal.ToArray());
    }

    [Fact]
    public async Task PatrolWritesOnlyChangesFromNormal()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        var firewall = new TestFirewall(order);
        firewall.PatrolResults.Enqueue(new FirewallIneffectiveException("测试巡检失败"));
        firewall.PatrolResults.Enqueue(new FirewallIneffectiveException("测试巡检失败"));
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        const string alarm = "巡检：系统防火墙已被关闭或被策略覆盖";
        await FireAndSettle(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        await Until(() => CountPrefix(journal.ToArray(), alarm) == 1);
        Assert.Equal(1, CountPrefix(journal.ToArray(), alarm));
        await FireAndSettle(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        await Until(() => timers.For("巡检").Length >= 3);
        Assert.Equal(1, CountPrefix(journal.ToArray(), alarm));
        await FireAndSettle(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        await Until(() => journal.Any(line => line == "巡检：恢复正常"));
        Assert.Contains("巡检：恢复正常", journal.ToArray());
    }

    [Fact]
    public async Task UnexpectedExceptionOnFirstConnectStillRestoresNetwork()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order) { ApplyError = new NotSupportedException("意外") },
            new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal("连接失败，已恢复原来的网络，当前没有走澳洲出口。原因已写入诊断记录，请导出诊断发给管理员。",
            controller.Snapshot.Message);
        Assert.Contains("remove", order);
        var lines = journal.ToArray();
        Assert.Contains(lines, line => line.StartsWith("动作出错：套用断网保护，用时 ", StringComparison.Ordinal)
            && line.Contains("NotSupportedException：意外"));
        Assert.Contains(lines, line => line.StartsWith("连接失败：NotSupportedException：意外", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UnexpectedExceptionWithHeldProtectionStillPropagates()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order) { HasPendingState = true, ApplyError = new NotSupportedException("意外") },
            new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        await Assert.ThrowsAsync<NotSupportedException>(() => controller.InitializeAsync(autoConnect: false, keepProtection: true));
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task UnexpectedRemoveFailureDuringAbandonNeedsManualAndKeepsProtection()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        var abandoned = 0;
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order)
            {
                ApplyError = new WfpUnavailableException("测试过滤层失败"),
                RemoveError = new NotSupportedException("撤销意外")
            },
            new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        controller.AttemptAbandoned += () => Interlocked.Increment(ref abandoned);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal("连接失败，原来的网络没能恢复：请点「断开」再试一次，还不行就重启电脑。原因：系统过滤层的保护没能建立。",
            controller.Snapshot.Message);
        Assert.Equal(1, Volatile.Read(ref abandoned));
        Assert.Contains(journal.ToArray(), line => line.StartsWith("撤销断网保护没成功：NotSupportedException：撤销意外", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UnexpectedExceptionInBackoffCallbackOnFirstAttemptRestores()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        var journal = new ConcurrentQueue<string>();
        var tunnel = new TestTunnel(order) { StartError = new IOException("测试断线") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = journal.Enqueue };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var scheduled = await timers.TakeAsync("退避", timeout.Token);
        Assert.Equal(TimeSpan.FromSeconds(2), scheduled.Delay);
        tunnel.StartError = new NotSupportedException("意外退避");
        scheduled.Completion.SetResult();
        await Until(() => controller.Snapshot.State == ConnectionState.Disconnected &&
            controller.Snapshot.Message.StartsWith("连接失败，已恢复原来的网络，当前没有走澳洲出口。", StringComparison.Ordinal));
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Contains("remove", order);
    }

    [Fact]
    public async Task JournalSubscriberFailureDoesNotBreakConnect()
    {
        var order = new List<string>();
        var timers = new TestTimers();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new TestFirewall(order), new TestTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay, Journal = _ => throw new InvalidOperationException("记录订阅者抛错") };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
    }
}
