using System.Net;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.State;
using WinClient.Core.Storage;
using Xunit;

namespace WinClient.Tests;

public sealed class ControllerTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StartupKeepsPairingProtectionAndConnectsRegardlessOfAutoConnect(bool autoConnect)
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        var snapshots = new List<ClientSnapshot>();
        controller.Changed += snapshots.Add;
        await controller.InitializeAsync(autoConnect, keepProtection: true);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("保持", controller.Snapshot.Message);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains(snapshots, snapshot => snapshot.Message == "后台服务已重新启动，断网保护保持，正在恢复连接。");
        Assert.All(snapshots, snapshot => Assert.True(snapshot.ProtectionActive));
    }

    [Fact]
    public async Task StartupPendingProtectionWithoutServerRecovers()
    {
        var order = new List<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.Equal(new[] { "recover" }, order);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Contains("未配置服务器", controller.Snapshot.Message);
    }

    [Fact]
    public async Task StartupPendingProtectionWithoutCredentialsRecovers()
    {
        var order = new List<string>();
        using var http = new HttpClient(new AuthTests.Handler(_ => throw new InvalidOperationException("不应请求会话")))
        { BaseAddress = new("https://192.0.2.1") };
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), new InMemoryCredentialStore()),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.Equal(new[] { "recover" }, order);
        Assert.False(controller.Snapshot.ProtectionActive);
    }

    [Fact]
    public async Task StartupWithoutPendingStateStillRecoversThenAutomaticallyConnects()
    {
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.Equal(new[] { "recover", "apply", "start" }, order);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OnlyAuthModePassesAuthEndpointToFirewall(bool authMode)
    {
        var order = new List<string>();
        var firewall = new Firewall(order);
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        ISessionSource source = authMode ? new AuthServerSessionSource(new AuthApiClient(http), store)
            : new PairingSessionSource(PairingTests.ValidPairing());
        var endpoint = new AuthEndpoint(IPAddress.Parse("192.0.2.1"), 8443, Path.GetFullPath("service.exe"));
        using var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, authEndpoint: endpoint);
        await controller.ConnectAsync();
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.Equal(authMode ? endpoint : null, firewall.AppliedAuth);
    }

    [Fact]
    public async Task StartupAuthNetworkRetriesExhaustWithoutEverRemovingProtection()
    {
        var pending = System.Threading.Channels.Channel.CreateUnbounded<(TimeSpan Delay, TaskCompletionSource Completion)>();
        Task Delay(TimeSpan duration, CancellationToken token)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            token.Register(() => completion.TrySetCanceled(token));
            pending.Writer.TryWrite((duration, completion));
            return completion.Task;
        }
        var order = new List<string>();
        var calls = 0;
        using var http = new HttpClient(new AuthTests.Handler(_ =>
        { Interlocked.Increment(ref calls); throw new HttpRequestException("测试网络不可达"); }))
        { BaseAddress = new("https://192.0.2.1") };
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), store),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, Delay);
        var snapshots = new System.Collections.Concurrent.ConcurrentQueue<ClientSnapshot>();
        var manual = new TaskCompletionSource<ClientSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.Changed += snapshot =>
        {
            snapshots.Enqueue(snapshot);
            if (snapshot.State == ConnectionState.NeedsManual && snapshot.Message.Contains("多次重连仍未成功")) manual.TrySetResult(snapshot);
        };
        await controller.InitializeAsync(true, true);
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60 })
        {
            var scheduled = await pending.Reader.ReadAsync(timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            scheduled.Completion.SetResult();
        }
        var result = await manual.Task.WaitAsync(timeout.Token);
        Assert.Equal(ConnectionState.NeedsManual, result.State);
        Assert.True(result.ProtectionActive);
        Assert.All(snapshots, snapshot => Assert.True(snapshot.ProtectionActive));
        Assert.Equal(12, Volatile.Read(ref calls));
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
    }

    [Fact]
    public async Task RecoveryWarningRemainsVisibleAfterAutomaticConnect()
    {
        var order = new List<string>();
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        const string warning = "上次断网保护已降级恢复，请管理员检查记录。";
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { RecoveryWarning = warning }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Contains(warning, controller.Snapshot.Message);
        Assert.NotEqual(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(order.IndexOf("recover") >= 0 && order.IndexOf("apply") > order.IndexOf("recover"));
        Assert.Contains("start", order);
    }

    [Fact]
    public async Task RecoveryWarningAlsoExplainsMissingServer()
    {
        var order = new List<string>();
        const string warning = "上次断网保护已降级恢复。";
        using var controller = new ClientController(null, new InMemoryCredentialStore(),
            new Firewall(order) { RecoveryWarning = warning }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(warning + " 未配置服务器。", controller.Snapshot.Message);
        Assert.NotEqual(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.DoesNotContain("apply", order);
    }

    [Fact]
    public async Task FailedRecoveryNeedsManualAndExplainsPreservedRecord()
    {
        var order = new List<string>();
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { FailRecovery = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Contains("恢复记录已保留", controller.Snapshot.Message);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
    }

    [Fact]
    public async Task PairingRetriesReachManualWithAddressHintAndKeepProtection()
    {
        var pending = System.Threading.Channels.Channel.CreateUnbounded<(TimeSpan Delay, TaskCompletionSource Completion)>();
        var expiryTokens = new List<CancellationToken>();
        Task Delay(TimeSpan duration, CancellationToken token)
        {
            if (duration >= TimeSpan.FromDays(1)) { expiryTokens.Add(token); return Task.Delay(Timeout.Infinite, token); }
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            token.Register(() => completion.TrySetCanceled(token));
            pending.Writer.TryWrite((duration, completion));
            return completion.Task;
        }
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new PairingTests.FakeFirewall(order), new PairingTests.FakeTunnel(order, fail: true), Path.GetFullPath("fake.exe"), TestData.Device, Delay);
        var manual = new TaskCompletionSource<ClientSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.Changed += snapshot => { if (snapshot.State == ConnectionState.NeedsManual && snapshot.Message.Contains("出口地址可能已变")) manual.TrySetResult(snapshot); };
        await controller.ConnectAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60 })
        {
            var scheduled = await pending.Reader.ReadAsync(timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            scheduled.Completion.SetResult();
        }
        var result = await manual.Task.WaitAsync(timeout.Token);
        Assert.Equal(ConnectionState.NeedsManual, result.State);
        Assert.Contains("出口地址可能已变", result.Message);
        Assert.Contains("重新导出配对文件再导入", result.Message);
        Assert.True(result.ProtectionActive);
        Assert.Equal(12, order.Count(x => x == "start"));
        Assert.DoesNotContain("remove", order);
        var previousExpiry = Assert.Single(expiryTokens);
        await controller.ConnectAsync();
        Assert.True(previousExpiry.IsCancellationRequested);
        Assert.Equal(2, expiryTokens.Count);
    }
    [Fact]
    public async Task StartupRecoveryPrecedesConnectAndNodeChangeNeverRestores()
    {
        var order = new List<string>(); var host = "192.0.2.5";
        using var http = SessionHttp(() => TestData.Session(host));
        var firewall = new Firewall(order); var tunnel = new Tunnel(order);
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store, firewall, tunnel, Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(new[] { "recover", "apply", "start" }, order);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        host = "192.0.2.6";
        await controller.RefreshSessionAsync();
        Assert.Contains("update:192.0.2.6", order);
        Assert.DoesNotContain("remove", order);
        Assert.True(controller.Snapshot.ProtectionActive);
        await controller.DisconnectAsync();
        Assert.Equal("remove", order.Last());
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
    }
    [Fact]
    public async Task RejectedSessionNeverStartsTunnel()
    {
        var order = new List<string>();
        using var http = new HttpClient(new AuthTests.Handler(_ => new(HttpStatusCode.Forbidden))) { BaseAddress = new("https://unit.invalid") };
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.DoesNotContain("start", order); Assert.DoesNotContain("apply", order); Assert.DoesNotContain("remove", order);
    }
    [Fact]
    public async Task ApplyFailureDoesNotStartOrSilentlyRemoveProtection()
    {
        var order = new List<string>(); using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store, new Firewall(order) { FailApply = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("start", order); Assert.DoesNotContain("remove", order);
    }
    [Fact]
    public async Task IneffectiveFirewallKeepsProtectionAndShowsSpecificReasonWithoutStartingTunnel()
    {
        var order = new List<string>(); using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        const string explanation = "系统防火墙被策略覆盖，请断开后联系管理员。";
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { ApplyError = new FirewallIneffectiveException(explanation) },
            new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(explanation, controller.Snapshot.Message);
        Assert.Contains("apply", order);
        Assert.DoesNotContain("start", order);
        Assert.DoesNotContain("remove", order);
    }
    [Fact]
    public async Task MissingServerIsExplicitAndClosingDoesNotRemove()
    {
        var order = new List<string>();
        var controller = new ClientController(null, new InMemoryCredentialStore(), new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(); Assert.Equal("未配置服务器", controller.Snapshot.Message);
        controller.Dispose(); Assert.DoesNotContain("remove", order);
    }
    // ===== 会话续期（邀请码模式）=====

    [Fact]
    public async Task RenewWaitIsScheduledAtEightyPercentAlongsideExpiry()
    {
        var (controller, timers, _, _) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Contains(timers.Delays, d => Near(d, TimeSpan.FromHours(6 * 0.8)));
            Assert.Contains(timers.Delays, d => Near(d, TimeSpan.FromHours(6)));
        }
    }

    [Fact]
    public async Task RenewWithSameContentOnlySwapsSessionWithoutRestartingTunnel()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(7), token: "renewed-session")));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            await Until(() => timers.Count == 4);
            Assert.Equal(new[] { "apply", "start" }, order);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
            Assert.Equal(2, source.Calls);
            // 新会话的到期与续期等待已重新安排，说明控制器持有的会话到期时间已更新。
            Assert.Contains(timers.Delays.Skip(2), d => Near(d, TimeSpan.FromHours(7)));
            Assert.Contains(timers.Delays.Skip(2), d => Near(d, TimeSpan.FromHours(7 * 0.8)));
            // 旧会话的到期回调触发时不再生效。
            await controller.ConnectAsync(); // 已连接时直接返回，用作串行锁屏障。
            var published = Volatile.Read(ref timers.Published);
            timers.Fire(d => Near(d, TimeSpan.FromHours(6)));
            await Until(() => Volatile.Read(ref timers.Published) > published);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal(new[] { "apply", "start" }, order);
        }
    }

    [Fact]
    public async Task RenewNetworkFailureRetriesEveryFiveMinutesWithoutTouchingTunnel()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.Network));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            await Until(() => timers.Count == 3);
            Assert.Equal(TimeSpan.FromMinutes(5), timers.Delays[2]);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal(new[] { "apply", "start" }, order);
            Assert.True(controller.Snapshot.ProtectionActive);
            // 再次触发：服务器恢复，返回内容相同的新会话，回到只换会话的路径。
            source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(7), token: "renewed-session")));
            timers.Fire(d => d == TimeSpan.FromMinutes(5));
            await Until(() => timers.Count == 5);
            Assert.Equal(3, source.Calls);
            Assert.Equal(new[] { "apply", "start" }, order);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Contains(timers.Delays.Skip(3), d => Near(d, TimeSpan.FromHours(7)));
            Assert.Contains(timers.Delays.Skip(3), d => Near(d, TimeSpan.FromHours(7 * 0.8)));
        }
    }

    [Fact]
    public async Task RenewRejectedTokenNeedsLoginStopsTunnelAndKeepsProtection()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.InvalidToken));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            await Until(() => controller.Snapshot.State == ConnectionState.NeedsLogin);
            await Until(() => order.Contains("stop"));
            Assert.Equal(new[] { "apply", "start", "stop" }, order);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.DoesNotContain("remove", order);
        }
    }

    [Fact]
    public async Task RenewWithChangedNodeRestartsTunnelUnderProtection()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(7), token: "renewed-session",
                node: TestData.Node(host: "192.0.2.6"))));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            // 停内核后进入退避，并为新会话安排到期与续期等待。
            await Until(() => timers.Count == 5);
            Assert.Equal(new[] { "apply", "start", "update", "stop" }, order);
            Assert.True(controller.Snapshot.ProtectionActive);
            timers.Fire(d => d == TimeSpan.FromSeconds(2));
            await Until(() => controller.Snapshot.State == ConnectionState.Connected);
            await controller.ConnectAsync(); // 串行锁屏障，等退避回调结束。
            Assert.Equal(new[] { "apply", "start", "update", "stop", "start" }, order);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.Contains(timers.Delays, d => Near(d, TimeSpan.FromHours(7 * 0.8)));
        }
    }

    [Fact]
    public async Task PairingModeNeverSchedulesRenew()
    {
        var timers = new Timers();
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new PairingTests.FakeFirewall(order), new PairingTests.FakeTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        // 只有到期等待的第一段（一天）；若安排了续期，会再多出一段等待。
        Assert.Equal(TimeSpan.FromDays(1), Assert.Single(timers.Delays));
        Assert.DoesNotContain(timers.Delays, d => d < TimeSpan.FromDays(1));
    }

    [Fact]
    public async Task NoRenewWhenLessThanOneMinuteRemains()
    {
        var (controller, timers, _, _) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromSeconds(30)));
        using (controller)
        {
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            var expiry = Assert.Single(timers.Delays);
            Assert.True(expiry <= TimeSpan.FromSeconds(30));
        }
    }

    [Theory]
    [InlineData("host")]
    [InlineData("reality_port")]
    [InlineData("hy2_port")]
    [InlineData("sni")]
    [InlineData("reality_public_key")]
    [InlineData("short_id")]
    [InlineData("uuid")]
    [InlineData("hy2_password")]
    [InlineData("hy2_server_name")]
    [InlineData("hy2_certificate")]
    [InlineData("hy2_obfs_password")]
    [InlineData("singbox_config")]
    public void SameSessionDetectsAnyNodeOrConfigDifference(string field)
    {
        var baseline = TestData.SessionExpiringIn(TimeSpan.FromHours(6));
        var node = field switch
        {
            "host" => TestData.Node(host: "192.0.2.6"),
            "reality_port" => TestData.Node(realityPort: 444),
            "hy2_port" => TestData.Node(hy2Port: 8444),
            "sni" => TestData.Node(sni: "other.invalid"),
            "reality_public_key" => TestData.Node(realityPublicKey: "other-key"),
            "short_id" => TestData.Node(shortId: "other-short"),
            "uuid" => TestData.Node(uuid: "other-uuid"),
            "hy2_password" => TestData.Node(hy2Password: "other-password"),
            "hy2_server_name" => TestData.Node(hy2ServerName: "other-name"),
            "hy2_certificate" => TestData.Node(hy2Certificate: ["-----BEGIN CERTIFICATE-----", "other-cert", "-----END CERTIFICATE-----"]),
            "hy2_obfs_password" => TestData.Node(hy2ObfsPassword: "other-obfs-password"),
            _ => TestData.Node()
        };
        var config = field == "singbox_config"
            ? JsonSerializer.SerializeToElement(new { inbounds = new[] { new { type = "mixed" } } }) : TestData.Config;
        var changed = TestData.SessionExpiringIn(TimeSpan.FromHours(6), node: node, config: config);
        Assert.False(ClientController.SameSession(baseline, changed));
    }

    [Fact]
    public void SameSessionIgnoresTokenAndExpiry()
    {
        var a = TestData.SessionExpiringIn(TimeSpan.FromHours(6), token: "first", accountLifetime: TimeSpan.FromDays(1));
        var b = TestData.SessionExpiringIn(TimeSpan.FromHours(9), token: "second", accountLifetime: TimeSpan.FromDays(2));
        Assert.True(ClientController.SameSession(a, b));
    }

    private static bool Near(TimeSpan actual, TimeSpan expected) => (actual - expected).Duration() <= TimeSpan.FromMinutes(2);
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
    private static async Task<(ClientController Controller, Timers Timers, ScriptedSource Source, List<string> Order)> ConnectRenewable(
        SessionResponse first)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource();
        source.Enqueue(Ok(first));
        var controller = new ClientController(source, new PairingTests.FakeFirewall(order), new PairingTests.FakeTunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay);
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        return (controller, timers, source, order);
    }
    /// <summary>可脚本化的会话来源：按调用次序返回预设结果；标记为需要续期的来源。</summary>
    private sealed class ScriptedSource : IRenewableSessionSource
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<AuthResponse<SessionResponse>> script = new();
        private int calls;
        public int Calls => Volatile.Read(ref calls);
        public string Mode => "邀请码模式";
        public void Enqueue(AuthResponse<SessionResponse> response) => script.Enqueue(response);
        public Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref calls);
            return script.TryDequeue(out var next) ? Task.FromResult(next)
                : throw new InvalidOperationException("测试脚本没有预设下一次会话结果。");
        }
    }
    /// <summary>记录每次等待并返回可手动完成的任务；测试按需触发某个等待。</summary>
    private sealed class Timers
    {
        private readonly List<(TimeSpan Delay, TaskCompletionSource Completion)> entries = [];
        public int Published;
        public TimeSpan[] Delays { get { lock (entries) return entries.Select(e => e.Delay).ToArray(); } }
        public int Count { get { lock (entries) return entries.Count; } }
        public Task Delay(TimeSpan delay, CancellationToken token)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            token.Register(() => completion.TrySetCanceled(token));
            lock (entries) entries.Add((delay, completion));
            return completion.Task;
        }
        public void Fire(Func<TimeSpan, bool> match)
        {
            TaskCompletionSource target;
            lock (entries) target = entries.First(e => !e.Completion.Task.IsCompleted && match(e.Delay)).Completion;
            target.SetResult();
        }
    }

    private static HttpClient SessionHttp(Func<SessionResponse> response) => new(new AuthTests.Handler(_ => new(HttpStatusCode.OK)
    { Content = new StringContent(JsonSerializer.Serialize(response(), new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })) }))
    { BaseAddress = new("https://unit.invalid") };
    private sealed class Firewall(List<string> order) : IKillSwitch
    {
        public bool HasPendingState { get; set; }
        public AuthEndpoint? AppliedAuth { get; private set; }
        public string? RecoveryWarning { get; init; }
        public bool FailRecovery { get; init; }
        public bool FailApply { get; init; }
        public Exception? ApplyError { get; init; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null)
        { AppliedAuth = auth; order.Add("apply"); if (ApplyError is not null) throw ApplyError; if (FailApply) throw new InvalidOperationException(); return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port)
        { order.Add("update:" + ips[0]); return Task.CompletedTask; }
        public Task RemoveAsync() { order.Add("remove"); return Task.CompletedTask; }
        public Task<string?> RecoverAsync()
        { order.Add("recover"); if (FailRecovery) throw new InvalidOperationException(); return Task.FromResult(RecoveryWarning); }
    }
    private sealed class Tunnel(List<string> order) : ITunnelTransport
    {
        public event EventHandler? TunnelDown { add { } remove { } }
        public Task StartAsync(JsonElement configuration, CancellationToken cancellationToken) { order.Add("start"); return Task.CompletedTask; }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }
}
