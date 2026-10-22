using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.Tests;

public sealed class UpdateIpcTests
{
    [Fact]
    public async Task CheckReturnsProgressAndChangedPushesExtendedSnapshot()
    {
        using var temp = new TempDirectory();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var updates = new FakeUpdates();
        var server = new ControlServer(new Facade(), new DesiredStateStore(temp.Path), updates, "1.2.3");
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, timeout.Token);
        using (var client = new ControlClient(peer))
        {
            var pushed = new TaskCompletionSource<ControlSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.SnapshotChanged += s => { if (s.Update.Stage == "downloading") pushed.TrySetResult(s); };
            Assert.True((await client.SendAsync("subscribe", cancellationToken: timeout.Token)).Ok);
            var response = await client.SendAsync("check_update", cancellationToken: timeout.Token);
            Assert.True(response.Ok); Assert.Equal(1, updates.Checks);
            Assert.Equal("1.2.3", response.Snapshot!.ServiceVersion);
            using var json = JsonDocument.Parse(ControlProtocol.Encode(response));
            Assert.Equal("checking", json.RootElement.GetProperty("snapshot").GetProperty("update").GetProperty("stage").GetString());
            updates.Publish();
            Assert.Equal("1.2.3", (await pushed.Task.WaitAsync(timeout.Token)).ServiceVersion);
        }
        await serving.WaitAsync(timeout.Token);
    }

    [Fact]
    public void NullCoordinatorStillHasVersionAndIdleStatus()
    {
        var snapshot = new ControlSnapshot(ConnectionState.Disconnected, "", "", false);
        Assert.NotEmpty(snapshot.ServiceVersion); Assert.Equal("idle", snapshot.Update.Stage);
    }

    private sealed class FakeUpdates : IUpdateCoordinator
    {
        public int Checks;
        public UpdateStatus Status { get; private set; } = new();
        public event Action<UpdateStatus>? Changed;
        public Task<UpdateStatus> CheckNowAsync() { Checks++; Status = new("checking"); return Task.FromResult(Status); }
        public void Publish() { Status = new("downloading", "2.0.0", "正在下载。"); Changed?.Invoke(Status); }
    }
    private sealed class Facade : IClientFacade
    {
        public Task SetRoutingAsync(string mode, IReadOnlyList<string> apps) => Task.CompletedTask;
        public Task SetEnvironmentEnabledAsync(bool enabled) => Task.CompletedTask;
        public Task RestoreEnvironmentAsync() => Task.CompletedTask;
        public ClientSnapshot Snapshot => new(ConnectionState.Connected, "已连接", "", true);
        public event Action<ClientSnapshot>? Changed { add { } remove { } }
        public Task ConnectAsync() => Task.CompletedTask;
        public Task DisconnectAsync() => Task.CompletedTask;
        public Task RedeemAsync(string code) => Task.CompletedTask;
        public Task ImportPairingAsync(string json) => Task.CompletedTask;
        public Task ClearPairingAsync() => Task.CompletedTask;
        public string? ReadAudit() => null;
        public string? ReadSelfCheck() => null;
    }
}
