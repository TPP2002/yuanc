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
    public void RoutingFieldsRoundTripAndOldSnapshotsDefaultToGlobal()
    {
        var value = new ClientSnapshot(ConnectionState.Disconnected, "", "", false)
            { RoutingMode = "apps", RoutingApps = [RoutingTests.Chrome] };
        var json = ControlProtocol.Encode(new ControlResponse(1, true, Snapshot: value));
        Assert.Contains("routing_mode", json); Assert.Contains("routing_apps", json);
        ClientSnapshot restored = ControlProtocol.DecodeResponse(json).Snapshot!;
        Assert.Equal(value.RoutingMode, restored.RoutingMode); Assert.Equal(value.RoutingApps, restored.RoutingApps);
        var old = ControlProtocol.DecodeResponse("{\"id\":1,\"ok\":true,\"snapshot\":{\"state\":\"Disconnected\",\"status\":\"\",\"message\":\"\",\"protection_active\":false}}").Snapshot!;
        Assert.Equal("global", old.RoutingMode); Assert.Empty(old.RoutingApps);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RoutingCommandRequiresModeAndTrustedCaller(bool trusted)
    {
        using var temp = new TempDirectory(); using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade(); var desired = new DesiredStateStore(temp.Path);
        var server = new ControlServer(facade, desired); var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token, callerTrusted: trusted);
        using (var client = new ControlClient(peer))
        {
            var missing = await client.SendAsync("set_routing", cancellationToken: stop.Token);
            Assert.False(missing.Ok); Assert.Equal(trusted ? "指令缺少 mode" : ControlServer.UntrustedCallerError, missing.Error);
            Assert.Empty(facade.Actions);
            var response = await client.SendAsync("set_routing", mode: "apps", apps: [RoutingTests.Chrome], cancellationToken: stop.Token);
            Assert.Equal(trusted, response.Ok);
            if (trusted)
            {
                Assert.Equal(new[] { "routing:apps" }, facade.Actions);
                Assert.Equal(new[] { RoutingTests.Chrome }, response.Snapshot!.RoutingApps);
                response = await client.SendAsync("set_routing", mode: "global", cancellationToken: stop.Token);
                Assert.True(response.Ok); Assert.Empty(response.Snapshot!.RoutingApps);
            }
            else { Assert.Equal(ControlServer.UntrustedCallerError, response.Error); Assert.Empty(facade.Actions); }
            Assert.Null(desired.Read());
        }
        await serving.WaitAsync(stop.Token);
    }
    [Fact]
    public void SelfCheckSnapshotRoundTripsAndLegacyDefaultsToNotChecked()
    {
        var snapshot = new ClientSnapshot(ConnectionState.Connected, "已连接", "", true) { SelfCheckStatus = "8 项通过" };
        var encoded = ControlProtocol.Encode(new ControlResponse(1, true, Snapshot: snapshot));
        Assert.Contains("self_check_status", encoded);
        ClientSnapshot decoded = ControlProtocol.DecodeResponse(encoded).Snapshot!;
        Assert.Equal(snapshot, decoded);
        var legacy = ControlProtocol.DecodeResponse("{\"id\":1,\"ok\":true,\"snapshot\":{\"state\":\"Disconnected\",\"status\":\"\",\"message\":\"\",\"protection_active\":false}}").Snapshot!;
        Assert.Equal("未检测", legacy.SelfCheckStatus);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ReadSelfCheckAllowsUntrustedCallersAndPreservesContent(bool trusted)
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade();
        var desired = new DesiredStateStore(temp.Path);
        var server = new ControlServer(facade, desired);
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token, callerTrusted: trusted);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("read_selfcheck", cancellationToken: stop.Token);
            Assert.True(response.Ok); Assert.Equal(facade.ReadSelfCheck(), response.SelfCheck);
            Assert.Empty(facade.Actions); Assert.Null(desired.Read());
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public void EnvironmentSnapshotRoundTripsAndLegacyDefaultsRemainEnabled()
    {
        var snapshot = new ClientSnapshot(ConnectionState.Connected, "已连接", "", true)
        { EnvironmentEnabled = false, EnvironmentStatus = "未启用" };
        ControlSnapshot control = snapshot;
        var encoded = ControlProtocol.Encode(new ControlResponse(1, true, Snapshot: control));
        Assert.Contains("environment_enabled", encoded);
        Assert.Contains("environment_status", encoded);
        var decoded = ControlProtocol.DecodeResponse(encoded).Snapshot!;
        Assert.False(decoded.EnvironmentEnabled);
        Assert.Equal("未启用", decoded.EnvironmentStatus);
        ClientSnapshot restored = decoded;
        Assert.Equal(snapshot, restored);
        var legacy = ControlProtocol.DecodeResponse("{\"id\":1,\"ok\":true,\"snapshot\":{\"state\":\"Disconnected\",\"status\":\"\",\"message\":\"\",\"protection_active\":false}}").Snapshot!;
        Assert.True(legacy.EnvironmentEnabled);
        Assert.Equal("未应用", legacy.EnvironmentStatus);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EnvironmentCommandRequiresEnabledAndTrustedCaller(bool trusted)
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade();
        var desired = new DesiredStateStore(temp.Path);
        var server = new ControlServer(facade, desired);
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token, callerTrusted: trusted);
        using (var client = new ControlClient(peer))
        {
            var missing = await client.SendAsync("set_environment", cancellationToken: stop.Token);
            Assert.False(missing.Ok);
            Assert.Equal(trusted ? "指令缺少 enabled" : ControlServer.UntrustedCallerError, missing.Error);
            Assert.Empty(facade.Actions);
            var response = await client.SendAsync("set_environment", enabled: false, cancellationToken: stop.Token);
            Assert.Equal(trusted, response.Ok);
            if (trusted)
            {
                Assert.Equal(new[] { "environment:False" }, facade.Actions);
                Assert.False(response.Snapshot!.EnvironmentEnabled);
                Assert.Equal("未启用", response.Snapshot.EnvironmentStatus);
            }
            else { Assert.Equal(ControlServer.UntrustedCallerError, response.Error); Assert.Empty(facade.Actions); }
            Assert.Null(desired.Read());
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public void ExitAndGuardFieldsRoundTripThroughBothSnapshotConversions()
    {
        var snapshot = new ClientSnapshot(ConnectionState.Connected, "已连接", "", true)
        { ExitStatus = "已核验", ExitIp = "192.0.2.5", GuardStatus = "正常" };
        ControlSnapshot control = snapshot;
        var encoded = ControlProtocol.Encode(new ControlResponse(7, true, Snapshot: control));
        Assert.Contains("exit_status", encoded);
        Assert.Contains("exit_ip", encoded);
        Assert.Contains("guard_status", encoded);
        var decoded = ControlProtocol.DecodeResponse(encoded).Snapshot!;
        Assert.Equal(snapshot.ExitStatus, decoded.ExitStatus);
        Assert.Equal(snapshot.ExitIp, decoded.ExitIp);
        Assert.Equal(snapshot.GuardStatus, decoded.GuardStatus);
        ClientSnapshot restored = decoded;
        Assert.Equal(snapshot, restored);
        var legacy = ControlProtocol.DecodeResponse("{\"id\":1,\"ok\":true,\"snapshot\":{\"state\":\"Disconnected\",\"status\":\"\",\"message\":\"\",\"protection_active\":false}}").Snapshot!;
        Assert.Equal("未检测", legacy.ExitStatus);
        Assert.Equal("", legacy.ExitIp);
        Assert.Equal("", legacy.GuardStatus);
    }

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
    public async Task StatusDoesNotWaitBehindQueuedCommand()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var facade = new FakeFacade { ConnectGate = gate };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (first, firstHost) = DuplexStream.Pair();
        var (second, secondHost) = DuplexStream.Pair();
        var serving = Task.WhenAll(server.ServeAsync(firstHost, stop.Token), server.ServeAsync(secondHost, stop.Token));
        using (var a = new ControlClient(first))
        using (var b = new ControlClient(second))
        {
            var connecting = a.SendAsync("connect", cancellationToken: stop.Token);
            await facade.ConnectEntered.Task.WaitAsync(stop.Token);
            // connect 占着指令信号量时，另一条连接的 status 仍须在 1 秒内拿到快照。
            var status = await b.SendAsync("status", cancellationToken: stop.Token).WaitAsync(TimeSpan.FromSeconds(1), stop.Token);
            Assert.True(status.Ok); Assert.NotNull(status.Snapshot);
            Assert.False(connecting.IsCompleted);
            gate.SetResult();
            Assert.True((await connecting.WaitAsync(stop.Token)).Ok);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task IdleUnsubscribedConnectionIsClosedButSubscribedOneStays()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path), idleTimeout: TimeSpan.FromMilliseconds(200));
        var (idle, idleHost) = DuplexStream.Pair();
        var (subscribed, subscribedHost) = DuplexStream.Pair();
        var idleServing = server.ServeAsync(idleHost, stop.Token);
        var subscribedServing = server.ServeAsync(subscribedHost, stop.Token);
        using (idle)
        using (var client = new ControlClient(subscribed))
        {
            Assert.True((await client.SendAsync("subscribe", cancellationToken: stop.Token)).Ok);
            var waited = Task.Delay(600, stop.Token);
            await idleServing.WaitAsync(TimeSpan.FromMilliseconds(600), stop.Token);
            Assert.Equal(0, await idle.ReadAsync(new byte[1], stop.Token));
            await waited;
            Assert.False(subscribedServing.IsCompleted);
            var status = await client.SendAsync("status", cancellationToken: stop.Token);
            Assert.True(status.Ok); Assert.NotNull(status.Snapshot);
        }
        await subscribedServing.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task RequestsResetIdleTimer()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path), idleTimeout: TimeSpan.FromMilliseconds(200));
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            for (var i = 0; i < 6; i++)
            {
                Assert.True((await client.SendAsync("status", cancellationToken: stop.Token)).Ok);
                await Task.Delay(100, stop.Token);
            }
            Assert.False(serving.IsCompleted);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task ZeroIdleTimeoutNeverClosesIdleConnection()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new ControlServer(new FakeFacade(), new DesiredStateStore(temp.Path), idleTimeout: TimeSpan.Zero);
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            await Task.Delay(600, stop.Token);
            Assert.False(serving.IsCompleted);
            Assert.True((await client.SendAsync("status", cancellationToken: stop.Token)).Ok);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public void TrustedServerRequiresServiceSessionAndImageUnderAppRoot()
    {
        var root = Path.GetFullPath("Program Files/YuanC/app");
        var exe = Path.Combine(root, "1.0.0", "YuanC-Client.exe");
        Assert.True(ServerIdentity.IsTrusted(0, 0, exe, root));
        // 大小写与 appRoot 尾部斜杠差异不影响判定。
        Assert.True(ServerIdentity.IsTrusted(0, 0, exe.ToUpperInvariant(), root.ToLowerInvariant()));
        Assert.True(ServerIdentity.IsTrusted(0, 0, exe, root + Path.DirectorySeparatorChar));
        Assert.False(ServerIdentity.IsTrusted(1, 0, exe, root));
        Assert.False(ServerIdentity.IsTrusted(0, 1, exe, root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, Path.GetFullPath("Program Files/Evil/YuanC-Client.exe"), root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, Path.GetFullPath("Program Files/YuanC/app-evil/YuanC-Client.exe"), root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, root, root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, root + Path.DirectorySeparatorChar, root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, root + @"\1.0.0\..\..\Evil\YuanC-Client.exe", root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, root + @"\1.0.0\..\2.0.0\YuanC-Client.exe", root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, @"YuanC\app\1.0.0\YuanC-Client.exe", root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, null, root));
        Assert.False(ServerIdentity.IsTrusted(0, 0, "", root));
    }

    [Fact]
    public async Task UntrustedCallerCannotChangeStateButCanRead()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade();
        var desired = new DesiredStateStore(temp.Path);
        var server = new ControlServer(facade, desired);
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token, callerTrusted: false);
        using (var client = new ControlClient(peer))
        {
            // 五个会改变连接状态的指令一律被拒：不调门面、不写期望状态。
            foreach (var (op, code, pairing) in new (string, string?, string?)[] { ("connect", null, null), ("disconnect", null, null), ("redeem", "邀请码", null), ("import_pairing", null, "配对正文"), ("clear_pairing", null, null) })
            {
                var rejected = await client.SendAsync(op, code: code, pairingJson: pairing, cancellationToken: stop.Token);
                Assert.False(rejected.Ok);
                Assert.Equal(ControlServer.UntrustedCallerError, rejected.Error);
                Assert.Null(rejected.Snapshot);
            }
            Assert.Empty(facade.Actions);
            Assert.Null(desired.Read());
            Assert.False(File.Exists(Path.Combine(temp.Path, "desired.json")));
            // 同一连接上的只读指令照常可用。
            foreach (var op in new[] { "status", "subscribe", "check_update" })
            {
                var reply = await client.SendAsync(op, cancellationToken: stop.Token);
                Assert.True(reply.Ok); Assert.NotNull(reply.Snapshot);
            }
            var audit = await client.SendAsync("read_audit", cancellationToken: stop.Token);
            Assert.True(audit.Ok); Assert.Equal("完整审计", audit.Audit);
            Assert.Empty(facade.Actions);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task DefaultCallerTrustKeepsExistingBehavior()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade();
        var desired = new DesiredStateStore(temp.Path);
        var server = new ControlServer(facade, desired);
        var (peer, host) = DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var reply = await client.SendAsync("connect", cancellationToken: stop.Token);
            Assert.True(reply.Ok); Assert.Null(reply.Error);
            Assert.Equal(new[] { "connect" }, facade.Actions);
            Assert.True(desired.Read());
        }
        await serving.WaitAsync(stop.Token);
    }

    // {root} 为安装目录，{ROOT} 为其大写，{parent} 为安装目录的父目录。
    [Theory]
    [InlineData("{root}/1.0.0/YuanC-Client.exe", true)]
    [InlineData("{root}/1.0.0/sub/YuanC-Updater.exe", true)]
    [InlineData("{ROOT}/1.0.0/YUANC-CLIENT.EXE", true)]
    [InlineData("{root}", false)]
    [InlineData("{root}/", false)]
    [InlineData("{parent}/YuanC-Client.exe", false)]
    [InlineData("{parent}", false)]
    [InlineData("{root}/1.0.0/../../Evil/YuanC-Client.exe", false)]
    [InlineData("{root}/1.0.0/../2.0.0/YuanC-Client.exe", false)]
    [InlineData("YuanC/app/1.0.0/YuanC-Client.exe", false)]
    [InlineData("{parent}-evil/x.exe", false)]
    [InlineData("{root}-evil/YuanC-Client.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void CallerIdentityTrustsOnlyImagesUnderAppRoot(string? template, bool expected)
    {
        var root = Path.GetFullPath("Program Files/YuanC/app");
        var parent = Path.GetDirectoryName(root)!;
        var image = template?.Replace("{root}", root).Replace("{ROOT}", root.ToUpperInvariant()).Replace("{parent}", parent);
        Assert.Equal(expected, CallerIdentity.IsTrusted(image, root));
        // appRoot 尾部带斜杠或大小写不同，判定结果不变。
        Assert.Equal(expected, CallerIdentity.IsTrusted(image, root.ToLowerInvariant() + Path.DirectorySeparatorChar));
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
        public Task SetRoutingAsync(string mode, IReadOnlyList<string> apps)
        {
            Actions.Add("routing:" + mode); Snapshot = Snapshot with { RoutingMode = mode, RoutingApps = apps.ToArray() };
            Changed?.Invoke(Snapshot); return Task.CompletedTask;
        }
        public Task SetEnvironmentEnabledAsync(bool enabled)
        {
            Actions.Add("environment:" + enabled);
            Snapshot = Snapshot with { EnvironmentEnabled = enabled, EnvironmentStatus = enabled ? "未应用" : "未启用" };
            Changed?.Invoke(Snapshot);
            return Task.CompletedTask;
        }
        public List<string> Actions { get; } = [];
        public ClientSnapshot Snapshot { get; private set; } = new(ConnectionState.Disconnected, "未连接", "", false);
        public event Action<ClientSnapshot>? Changed;
        public Action<ClientSnapshot>? CaptureChanged() => Changed;
        // 为空时行为与原来一致；测试 status 不排队时用它把 connect 卡住。
        public TaskCompletionSource? ConnectGate { get; init; }
        public TaskCompletionSource ConnectEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task ConnectAsync()
        {
            Actions.Add("connect");
            ConnectEntered.TrySetResult();
            if (ConnectGate is { } gate) await gate.Task;
            Snapshot = new(ConnectionState.Connected, "已连接", "", true); Changed?.Invoke(Snapshot);
        }
        public Task DisconnectAsync() { Actions.Add("disconnect"); Snapshot = new(ConnectionState.Disconnected, "未连接", "", false); Changed?.Invoke(Snapshot); return Task.CompletedTask; }
        public Task RedeemAsync(string code) { Actions.Add("redeem:" + code); return Task.CompletedTask; }
        public Task ImportPairingAsync(string json) { Actions.Add("import:" + json); return Task.CompletedTask; }
        public Task ClearPairingAsync() { Actions.Add("clear"); return Task.CompletedTask; }
        public string? ReadAudit() => "完整审计";
        public string? ReadSelfCheck() => "{\"summary\":\"8 项通过\",\"items\":[]}";
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
