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
        public bool FailApply { get; init; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port)
        { order.Add("apply"); if (FailApply) throw new InvalidOperationException(); return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port)
        { order.Add("update:" + ips[0]); return Task.CompletedTask; }
        public Task RemoveAsync() { order.Add("remove"); return Task.CompletedTask; }
        public Task RecoverAsync() { order.Add("recover"); return Task.CompletedTask; }
    }
    private sealed class Tunnel(List<string> order) : ITunnelTransport
    {
        public event EventHandler? TunnelDown { add { } remove { } }
        public Task StartAsync(JsonElement configuration, CancellationToken cancellationToken) { order.Add("start"); return Task.CompletedTask; }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }
}
