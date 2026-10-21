using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using WinClient.Core.Client;
using WinClient.Core.Ipc;
using WinClient.Core.Pairing;
using WinClient.Core.State;
using WinClient.Core.Storage;
using Xunit;

namespace WinClient.Tests;

public sealed class IpcTests
{
    [Fact]
    public void ProtocolRoundTripsAndUsesContractNames()
    {
        var request = new ControlRequest(42, "import_pairing", PairingJson: "中文\n配对内容");
        var encoded = ControlProtocol.Encode(request);
        Assert.EndsWith("\n", encoded);
        Assert.Equal(request, ControlProtocol.DecodeRequest(encoded));
        Assert.Contains("pairing_json", encoded);
        var snapshot = new ClientSnapshot(ConnectionState.Connected, "已连接", "就绪", true) { Mode = "自用模式" };
        var response = new ControlResponse(42, true, Snapshot: snapshot, Audit: "审计");
        Assert.Equal(response, ControlProtocol.DecodeResponse(ControlProtocol.Encode(response)));
        Assert.Contains("protection_active", ControlProtocol.Encode(response));
    }

    [Fact]
    public async Task BadJsonAndUnknownOperationKeepConnectionAlive()
    {
        using var temp = new TempDirectory();
        var (peer, host) = DuplexStream.Pair();
        using (peer)
        using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path));
            var serving = server.ServeAsync(host, stop.Token);
            using var reader = new StreamReader(peer, Encoding.UTF8, leaveOpen: true);
            await peer.WriteAsync(Encoding.UTF8.GetBytes("{bad\n{\"id\":1,\"op\":\"unsupported\"}\n{\"id\":2,\"op\":\"status\"}\n"), stop.Token);
            var bad = ControlProtocol.DecodeResponse((await reader.ReadLineAsync(stop.Token))!);
            Assert.False(bad.Ok); Assert.Null(bad.Id); Assert.Equal("指令格式错误", bad.Error);
            var unknown = ControlProtocol.DecodeResponse((await reader.ReadLineAsync(stop.Token))!);
            Assert.False(unknown.Ok); Assert.Equal(1, unknown.Id); Assert.Equal("不支持的指令", unknown.Error);
            var status = ControlProtocol.DecodeResponse((await reader.ReadLineAsync(stop.Token))!);
            Assert.True(status.Ok); Assert.Equal(2, status.Id); Assert.NotNull(status.Snapshot);
            peer.Dispose();
            await serving.WaitAsync(stop.Token);
        }
    }

    [Fact]
    public async Task OversizeLineClosesOnlyThatConnection()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path));
        var (peer, host) = DuplexStream.Pair();
        using (peer)
        {
            var serving = server.ServeAsync(host, stop.Token);
            await peer.WriteAsync(new byte[ControlProtocol.MaxLineBytes + 1], stop.Token);
            await serving.WaitAsync(stop.Token);
            Assert.Equal(0, await peer.ReadAsync(new byte[1], stop.Token));
        }
        var (next, nextHost) = DuplexStream.Pair();
        var second = server.ServeAsync(nextHost, stop.Token);
        using (var client = new ControlClient(next))
            Assert.True((await client.SendAsync("status", cancellationToken: stop.Token)).Ok);
        await second.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task SubscriptionDesiredStateAuditAndTwoClientsAreIndependent()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade();
        var desired = new DesiredStateStore(temp.Path);
        var server = new ControlServer(facade, desired);
        var (first, firstHost) = DuplexStream.Pair();
        var (second, secondHost) = DuplexStream.Pair();
        var serving = Task.WhenAll(server.ServeAsync(firstHost, stop.Token), server.ServeAsync(secondHost, stop.Token));
        using (var a = new ControlClient(first))
        using (var b = new ControlClient(second))
        {
            var pushed = new TaskCompletionSource<ClientSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
            a.Changed += snapshot => { if (snapshot.Status == "已连接") pushed.TrySetResult(snapshot); };
            Assert.True((await a.SendAsync("subscribe", cancellationToken: stop.Token)).Ok);
            Assert.True((await b.SendAsync("connect", cancellationToken: stop.Token)).Ok);
            Assert.True(desired.Read());
            Assert.Equal("已连接", (await pushed.Task.WaitAsync(stop.Token)).Status);
            var replies = await Task.WhenAll(a.SendAsync("read_audit", cancellationToken: stop.Token), b.SendAsync("status", cancellationToken: stop.Token));
            Assert.Equal("完整审计", replies[0].Audit); Assert.Null(replies[1].Audit);
            Assert.True((await a.SendAsync("disconnect", cancellationToken: stop.Token)).Ok);
            Assert.False(desired.Read());
            Assert.Equal(new[] { "connect", "disconnect" }, facade.Actions);
            await a.SendAsync("redeem", code: "邀请码", cancellationToken: stop.Token);
            await b.SendAsync("import_pairing", pairingJson: "配对正文", cancellationToken: stop.Token);
            await b.SendAsync("clear_pairing", cancellationToken: stop.Token);
            Assert.Equal(new[] { "connect", "disconnect", "redeem:邀请码", "import:配对正文", "clear" }, facade.Actions);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public void DesiredStateMissingCorruptAndAtomicRoundTrip()
    {
        using var temp = new TempDirectory();
        var store = new DesiredStateStore(temp.Path);
        Assert.Null(store.Read());
        File.WriteAllText(Path.Combine(temp.Path, "desired.json"), "{broken");
        Assert.Null(store.Read());
        store.Write(true); Assert.True(store.Read());
        using (var json = JsonDocument.Parse(File.ReadAllText(Path.Combine(temp.Path, "desired.json"))))
            Assert.True(DateTimeOffset.TryParse(json.RootElement.GetProperty("updated_at").GetString(), out _));
        store.Write(false); Assert.False(store.Read());
        Assert.False(File.Exists(Path.Combine(temp.Path, "desired.json.tmp")));
    }

    [Fact]
    public async Task InFlightSnapshotAfterUnsubscribeDoesNotTouchDisposedConnection()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade();
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        Action<ClientSnapshot>? inFlight;
        using (var client = new ControlClient(peer))
        {
            Assert.True((await client.SendAsync("subscribe", cancellationToken: stop.Token)).Ok);
            inFlight = facade.CaptureChanged();
            Assert.NotNull(inFlight);
        }
        await serving.WaitAsync(stop.Token);
        Assert.Null(facade.CaptureChanged());
        inFlight!(facade.Snapshot);
    }

    [Fact]
    public async Task DisabledAutoConnectStillRecoversAndPublishesWithCredentials()
    {
        var order = new List<string>();
        using var http = new HttpClient(new AuthTests.Handler(_ => throw new InvalidOperationException("不应请求会话"))) { BaseAddress = new("https://unit.invalid") };
        var credentials = new InMemoryCredentialStore(); credentials.Save("test-refresh");
        using var controller = new ClientController(new WinClient.Core.Auth.AuthApiClient(http), credentials,
            new PairingTests.FakeFirewall(order), new PairingTests.FakeTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        var published = 0; controller.Changed += _ => published++;
        await controller.InitializeAsync(autoConnect: false);
        Assert.Equal(new[] { "recover" }, order);
        Assert.Equal(1, published);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
    }

    [Fact]
    public void MachineScopedStoresRoundTripInExplicitRoot()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var temp = new TempDirectory();
        var credentials = new DpapiCredentialStore("YuanC", root: temp.Path, scope: DataProtectionScope.LocalMachine);
        credentials.Save("test-refresh");
        Assert.Equal("test-refresh", new DpapiCredentialStore("YuanC", root: temp.Path, scope: DataProtectionScope.LocalMachine).Load());
        Assert.Equal("test-refresh", Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(temp.Path, "credential.bin")), null, DataProtectionScope.LocalMachine)));
        var pairing = new PairingStore(root: temp.Path, scope: DataProtectionScope.LocalMachine);
        pairing.Save(PairingTests.ValidPairing());
        Assert.Equal(PairingTests.ValidPairing().RawJson, new PairingStore(root: temp.Path, scope: DataProtectionScope.LocalMachine).Load()!.RawJson);
        Assert.Equal(PairingTests.ValidPairing().RawJson, Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(pairing.FilePath), null, DataProtectionScope.LocalMachine)));
        var fingerprint = ClientSettings.GetDeviceFingerprint(temp.Path, DataProtectionScope.LocalMachine);
        Assert.Equal(fingerprint, ClientSettings.GetDeviceFingerprint(temp.Path, DataProtectionScope.LocalMachine));
        var bytes = File.ReadAllBytes(Path.Combine(temp.Path, "device-id"));
        Assert.DoesNotContain(fingerprint, Encoding.UTF8.GetString(bytes));
        Assert.Equal(fingerprint, Encoding.UTF8.GetString(ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine)));
    }

    private sealed class FakeFacade : IClientFacade
    {
        public List<string> Actions { get; } = [];
        public ClientSnapshot Snapshot { get; private set; } = new(ConnectionState.Disconnected, "未连接", "", false);
        public event Action<ClientSnapshot>? Changed;
        public Action<ClientSnapshot>? CaptureChanged() => Changed;
        public Task ConnectAsync() { Actions.Add("connect"); Snapshot = new(ConnectionState.Connected, "已连接", "", true); Changed?.Invoke(Snapshot); return Task.CompletedTask; }
        public Task DisconnectAsync() { Actions.Add("disconnect"); Snapshot = new(ConnectionState.Disconnected, "未连接", "", false); Changed?.Invoke(Snapshot); return Task.CompletedTask; }
        public Task RedeemAsync(string code) { Actions.Add("redeem:" + code); return Task.CompletedTask; }
        public Task ImportPairingAsync(string json) { Actions.Add("import:" + json); return Task.CompletedTask; }
        public Task ClearPairingAsync() { Actions.Add("clear"); return Task.CompletedTask; }
        public string? ReadAudit() => "完整审计";
    }

    // Two independent byte queues: no OS pipes, sockets or production operations in tests.
    internal sealed class DuplexStream(Channel<byte[]> incoming, Channel<byte[]> outgoing) : Stream
    {
        private byte[]? current;
        private int offset;
        public static (Stream, Stream) Pair()
        {
            var a = Channel.CreateUnbounded<byte[]>(); var b = Channel.CreateUnbounded<byte[]>();
            return (new DuplexStream(a, b), new DuplexStream(b, a));
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (current is null || offset == current.Length)
            {
                if (!await incoming.Reader.WaitToReadAsync(cancellationToken)) return 0;
                if (!incoming.Reader.TryRead(out current)) continue;
                offset = 0;
            }
            var length = Math.Min(buffer.Length, current.Length - offset);
            current.AsMemory(offset, length).CopyTo(buffer); offset += length; return length;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => outgoing.Writer.WriteAsync(buffer.ToArray(), cancellationToken);
        protected override void Dispose(bool disposing) { outgoing.Writer.TryComplete(); base.Dispose(disposing); }
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
