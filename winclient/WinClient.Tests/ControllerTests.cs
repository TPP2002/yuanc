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
