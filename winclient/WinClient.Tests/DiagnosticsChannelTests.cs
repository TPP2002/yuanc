using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Client;
using WinClient.Core.Diagnostics;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using WinClient.Core.Process;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

/// <summary>测试包诊断补通道状态单的用例：只连本机回环上测试自建的监听端，不碰真系统与外部地址。</summary>
public sealed class DiagnosticsChannelTests
{
    [Fact]
    public void StatusEndpointOffKeepsConfigurationUnchanged()
    {
        var configuration = KernelConfiguration();
        Assert.Equal(TunnelTransport.RenderConfiguration(configuration).GetRawText(),
            TunnelTransport.RenderConfiguration(configuration, false, null).GetRawText());
        var on = TunnelTransport.RenderConfiguration(configuration, true);
        var explicitOn = TunnelTransport.RenderConfiguration(configuration, true, null);
        Assert.Equal(on.GetRawText(), explicitOn.GetRawText());
        using var document = JsonDocument.Parse(on.GetRawText());
        Assert.False(document.RootElement.TryGetProperty("experimental", out _));
    }

    [Fact]
    public void StatusEndpointOnAddsLoopbackStatusApi()
    {
        var configuration = KernelConfiguration();
        var withStatus = JsonNode.Parse(TunnelTransport.RenderConfiguration(
            configuration, true, new KernelStatusEndpoint(23456, "abc")).GetRawText())!.AsObject();
        Assert.Equal("127.0.0.1:23456",
            withStatus["experimental"]!["clash_api"]!["external_controller"]!.GetValue<string>());
        Assert.Equal("abc", withStatus["experimental"]!["clash_api"]!["secret"]!.GetValue<string>());
        var withoutStatus = JsonNode.Parse(TunnelTransport.RenderConfiguration(configuration, true, null).GetRawText())!.AsObject();
        withStatus.Remove("experimental");
        Assert.Equal(withoutStatus.ToJsonString(), withStatus.ToJsonString());

        var cached = JsonDocument.Parse(
            "{\"experimental\":{\"cache_file\":{\"enabled\":true}},\"inbounds\":[{\"type\":\"tun\"}]}").RootElement;
        var cacheRoot = JsonNode.Parse(TunnelTransport.RenderConfiguration(
            cached, true, new KernelStatusEndpoint(23456, "abc")).GetRawText())!.AsObject();
        Assert.True(cacheRoot["experimental"]!["cache_file"]!["enabled"]!.GetValue<bool>());
        Assert.Equal("abc", cacheRoot["experimental"]!["clash_api"]!["secret"]!.GetValue<string>());
    }

    [Fact]
    public void StatusEndpointCreatePicksLoopbackPortAndRandomSecret()
    {
        var first = KernelStatusEndpoint.Create();
        var second = KernelStatusEndpoint.Create();
        Assert.InRange(first.Port, 1024, 65535);
        Assert.InRange(second.Port, 1024, 65535);
        Assert.Matches("^[0-9A-F]{32}$", first.Secret);
        Assert.Matches("^[0-9A-F]{32}$", second.Secret);
        Assert.NotEqual(first.Secret, second.Secret);
        Assert.DoesNotContain(first.Secret, first.ToString());
    }

    [Fact]
    public void MainTargetReadsMainOutbound()
    {
        var config = JsonDocument.Parse("{\"outbounds\":[{\"tag\":\"backup\"}," +
            "{\"tag\":\"main\",\"server\":\"203.0.113.9\",\"server_port\":443,\"tls\":{\"server_name\":\"www.example.com\"}}]}").RootElement;
        Assert.Equal(new ReachTarget("203.0.113.9", 443, "www.example.com"), ReachProbe.MainTargetFrom(config));
        Assert.Null(ReachProbe.MainTargetFrom(JsonDocument.Parse("{\"outbounds\":[{\"tag\":\"backup\"}]}").RootElement));
        Assert.Null(ReachProbe.MainTargetFrom(JsonDocument.Parse(
            "{\"outbounds\":[{\"tag\":\"main\",\"server\":\"203.0.113.9\",\"tls\":{\"server_name\":\"www.example.com\"}}]}").RootElement));
        Assert.Null(ReachProbe.MainTargetFrom(JsonDocument.Parse(
            "{\"outbounds\":[{\"tag\":\"main\",\"server\":\"203.0.113.9\",\"server_port\":443,\"tls\":{}}]}").RootElement));
        Assert.Null(ReachProbe.MainTargetFrom(JsonDocument.Parse("[1,2,3]").RootElement));
    }

    private static JsonElement KernelConfiguration() => JsonDocument.Parse(
        "{\"log\":{\"disabled\":true},\"inbounds\":[{\"type\":\"tun\"}]}").RootElement;

    [Fact]
    public async Task TransportOpensStatusApiOnlyWhenKernelLogOn()
    {
        var configuration = TransportConfiguration();
        using var directory = new TempDirectory();
        var manager = new SingBoxProcessManager(CreateExecutable(directory), "YuanC", new QuietLauncher(),
            new AuthTests.MemoryLog(), directory.Path, new StrayKernelSweeper(new FakeKernelTable()));
        using var transport = new TunnelTransport(manager, () => true, (_, _) => Task.CompletedTask) { KernelLog = true };
        await transport.StartAsync(configuration, CancellationToken.None);
        Assert.NotNull(transport.StatusEndpoint);
        var saved = JsonNode.Parse(File.ReadAllText(manager.ConfigPath))!.AsObject();
        Assert.Equal($"127.0.0.1:{transport.StatusEndpoint!.Port}",
            saved["experimental"]!["clash_api"]!["external_controller"]!.GetValue<string>());
        Assert.Equal(transport.StatusEndpoint.Secret, saved["experimental"]!["clash_api"]!["secret"]!.GetValue<string>());
        Assert.Equal(new ReachTarget("203.0.113.9", 443, "www.example.com"), transport.MainTarget);
        transport.Stop();
        Assert.Null(transport.StatusEndpoint);
        Assert.NotNull(transport.MainTarget);

        using var offDirectory = new TempDirectory();
        var offManager = new SingBoxProcessManager(CreateExecutable(offDirectory), "YuanC", new QuietLauncher(),
            new AuthTests.MemoryLog(), offDirectory.Path, new StrayKernelSweeper(new FakeKernelTable()));
        using var offTransport = new TunnelTransport(offManager, () => true, (_, _) => Task.CompletedTask);
        await offTransport.StartAsync(configuration, CancellationToken.None);
        Assert.Null(offTransport.StatusEndpoint);
        Assert.Null(offTransport.MainTarget);
        var offSaved = JsonNode.Parse(File.ReadAllText(offManager.ConfigPath))!.AsObject();
        Assert.False(offSaved.ContainsKey("experimental"));
    }

    [Fact]
    public async Task ChannelProbeReportsSelectedAndDelays()
    {
        var handler = new StubHandler((request, _) =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/proxies")
                return Task.FromResult(Json("{\"proxies\":{\"proxy\":{\"now\":\"backup\"},\"main\":{\"history\":[]}," +
                    "\"backup\":{\"history\":[{\"time\":\"2026-11-28T05:20:35Z\",\"delay\":181}]}}}"));
            if (path == "/proxies/main/delay") return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            return Task.FromResult(Json("{\"delay\":158}"));
        });
        var endpoint = new KernelStatusEndpoint(23456, "secret-token");
        var result = await KernelChannelProbe.RunAsync(endpoint, handler, TimeSpan.FromSeconds(5));
        Assert.Null(result.Error);
        var json = JsonNode.Parse(result.Json!)!.AsObject();
        Assert.Equal("backup", json["selected"]!.GetValue<string>());
        Assert.Null(json["main"]!["last_delay_ms"]);
        Assert.Null(json["main"]!["last_test_at"]);
        Assert.False(json["main"]!["test_ok"]!.GetValue<bool>());
        Assert.Equal(503, json["main"]!["test_status"]!.GetValue<int>());
        Assert.Equal(181, json["backup"]!["last_delay_ms"]!.GetValue<int>());
        Assert.Equal("2026-11-28T05:20:35Z", json["backup"]!["last_test_at"]!.GetValue<string>());
        Assert.True(json["backup"]!["test_ok"]!.GetValue<bool>());
        Assert.Equal(158, json["backup"]!["test_delay_ms"]!.GetValue<int>());
        Assert.Equal(200, json["backup"]!["test_status"]!.GetValue<int>());
        Assert.Equal(3, handler.Requests.Count);
        Assert.All(handler.Requests, request =>
        {
            Assert.Equal("127.0.0.1", request.RequestUri!.Host);
            Assert.Equal(23456, request.RequestUri.Port);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("secret-token", request.Headers.Authorization.Parameter);
        });
        var delays = handler.Requests.Where(request => request.RequestUri!.AbsolutePath.EndsWith("/delay", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, delays.Length);
        Assert.All(delays, request =>
        {
            Assert.Contains("timeout=3000", request.RequestUri!.Query);
            Assert.Contains(Uri.EscapeDataString(KernelChannelProbe.TestUrl), request.RequestUri.Query);
        });
        Assert.DoesNotContain("secret-token", result.Json!);
    }

    [Fact]
    public async Task ChannelProbeReturnsFixedErrors()
    {
        var idle = new StubHandler((_, _) => Task.FromResult(Json("{}")));
        var notRunning = await KernelChannelProbe.RunAsync(null, idle);
        Assert.Equal(KernelChannelProbe.NotRunning, notRunning.Error);
        Assert.Empty(idle.Requests);

        var unauthorized = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)));
        Assert.Equal(KernelChannelProbe.Failed,
            (await KernelChannelProbe.RunAsync(new KernelStatusEndpoint(23456, "s"), unauthorized)).Error);

        var missing = new StubHandler((_, _) => Task.FromResult(Json("{\"proxies\":{}}")));
        Assert.Equal(KernelChannelProbe.Failed,
            (await KernelChannelProbe.RunAsync(new KernelStatusEndpoint(23456, "s"), missing)).Error);

        var thrown = new StubHandler((_, _) => throw new HttpRequestException("boom"));
        Assert.Equal(KernelChannelProbe.Failed,
            (await KernelChannelProbe.RunAsync(new KernelStatusEndpoint(23456, "s"), thrown)).Error);

        var slow = new StubHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return Json("{}");
        });
        Assert.Equal(KernelChannelProbe.TimedOut,
            (await KernelChannelProbe.RunAsync(new KernelStatusEndpoint(23456, "s"), slow, TimeSpan.FromMilliseconds(50))).Error);

        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => KernelChannelProbe.RunAsync(
            new KernelStatusEndpoint(23456, "s"), idle, null, cancel.Token));
    }

    private static JsonElement TransportConfiguration() => JsonSerializer.SerializeToElement(new
    {
        log = new { disabled = true },
        inbounds = new[] { new { type = "tun" } },
        outbounds = new object[]
        {
            new { type = "vless", tag = "main", server = "203.0.113.9", server_port = 443, tls = new { server_name = "www.example.com" } },
            new { type = "hysteria2", tag = "backup", server = "203.0.113.9", server_port = 8443 }
        }
    });

    private static string CreateExecutable(TempDirectory directory)
    {
        var path = Path.Combine(directory.Path, "fake.exe");
        File.WriteAllText(path, "fake kernel fixture");
        return path;
    }

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    [Fact]
    public async Task ReachProbeWithoutTargetReturnsFixedError()
    {
        var result = await ReachProbe.RunAsync(null, false);
        Assert.Null(result.Json);
        Assert.Equal(ReachProbe.NoTarget, result.Error);
    }

    [Fact]
    public async Task ReachProbeReportsRefused()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        // Windows 上连本机没人听的端口要 2 秒左右才返回拒绝，这条用默认时限，不要缩短。
        var result = await ReachProbe.RunAsync(new ReachTarget("127.0.0.1", port, "localhost"), false);
        Assert.Null(result.Error);
        var json = JsonNode.Parse(result.Json!)!.AsObject();
        Assert.Equal("refused", json["tcp"]!.GetValue<string>());
        Assert.Null(json["tls"]);
        Assert.False(json["bound"]!.GetValue<bool>());
    }

    [Fact]
    public async Task ReachProbeReportsHandshakeCutByPeer()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accepting = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            client.Close();
        });
        var result = await ReachProbe.RunAsync(new ReachTarget("127.0.0.1", port, "localhost"), false);
        await accepting;
        var json = JsonNode.Parse(result.Json!)!.AsObject();
        Assert.Equal("ok", json["tcp"]!.GetValue<string>());
        Assert.True(json["tcp_ms"]!.GetValue<int>() >= 0);
        var tls = json["tls"]!.GetValue<string>();
        Assert.True(tls is "closed" or "reset");
        Assert.Null(json["cert_issuer"]);
    }

    [Fact]
    public async Task ReachProbeReportsHandshakeTimeout()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var accepting = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            await gate.Task;
        });
        var result = await ReachProbe.RunAsync(new ReachTarget("127.0.0.1", port, "localhost"), false,
            TimeSpan.FromMilliseconds(300));
        gate.SetResult();
        await accepting;
        var json = JsonNode.Parse(result.Json!)!.AsObject();
        Assert.Equal("ok", json["tcp"]!.GetValue<string>());
        Assert.Equal("timeout", json["tls"]!.GetValue<string>());

        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReachProbe.RunAsync(
            new ReachTarget("127.0.0.1", 9, "localhost"), false, null, cancel.Token));
    }

    [Fact]
    public async Task ReachProbeReportsIssuerOnSuccess()
    {
        using var certificate = CreateSelfSigned();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accepting = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate });
            }
            catch (Exception) { }
        });
        var result = await ReachProbe.RunAsync(new ReachTarget("127.0.0.1", port, "localhost"), false);
        await accepting;
        var json = JsonNode.Parse(result.Json!)!.AsObject();
        Assert.Equal("ok", json["tcp"]!.GetValue<string>());
        Assert.Equal("ok", json["tls"]!.GetValue<string>());
        Assert.False(string.IsNullOrEmpty(json["tls_protocol"]!.GetValue<string>()));
        Assert.NotEqual("None", json["cert_errors"]!.GetValue<string>());
        Assert.Contains("YuanC-Test-CA", json["cert_issuer"]!.GetValue<string>());
        Assert.DoesNotContain("127.0.0.1", result.Json!);
        Assert.DoesNotContain("localhost", result.Json!);
    }

    private static X509Certificate2 CreateSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=YuanC-Test-CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pfx = created.Export(X509ContentType.Pfx);
        return X509CertificateLoader.LoadPkcs12(pfx, null);
    }

    [Fact]
    public async Task CollectorEmbedsChannelSectionsAndRedacts()
    {
        using var directory = new TempDirectory();
        var sources = new DiagnosticsSources
        {
            RunDirectory = directory.Path,
            Snapshot = () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false),
            Network = _ => Task.FromResult(new NetworkStateResult("{\"routes_active\":[]}", null)),
            Channels = _ => Task.FromResult(new ChannelStateResult("{\"selected\":\"backup\",\"note\":\"8.8.8.8\"}", null)),
            NodeReach = _ => Task.FromResult(new ReachResult(null, ReachProbe.NoTarget)),
            Ipv6Reach = _ => throw new InvalidOperationException("boom"),
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };
        var root = JsonNode.Parse(await DiagnosticsCollector.CollectAsync(sources))!.AsObject();
        Assert.Equal("backup", root["channels"]!["selected"]!.GetValue<string>());
        Assert.Equal("[公网地址]", root["channels"]!["note"]!.GetValue<string>());
        Assert.Null(root["channels_error"]);
        Assert.Null(root["node_reach"]);
        Assert.Equal(ReachProbe.NoTarget, root["node_reach_error"]!.GetValue<string>());
        Assert.Equal("InvalidOperationException", root["errors"]!["ipv6_reach"]!.GetValue<string>());
        Assert.Null(root["ipv6_reach"]);
        Assert.Null(root["ipv6_reach_error"]);
        Assert.NotNull(root["logs"]);
        var keys = root.Select(pair => pair.Key).ToArray();
        var index = Array.IndexOf(keys, "network_error");
        Assert.Equal(new[] { "channels", "channels_error", "node_reach", "node_reach_error", "ipv6_reach", "ipv6_reach_error", "logs" },
            keys.Skip(index + 1).Take(7));
    }

    [Fact]
    public async Task CollectorOmitsChannelSectionsWhenNotWired()
    {
        using var directory = new TempDirectory();
        var bare = new DiagnosticsSources
        {
            RunDirectory = directory.Path,
            Snapshot = () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false),
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };
        var bareKeys = JsonNode.Parse(await DiagnosticsCollector.CollectAsync(bare))!.AsObject().Select(pair => pair.Key).ToArray();
        foreach (var key in new[] { "channels", "channels_error", "node_reach", "node_reach_error", "ipv6_reach", "ipv6_reach_error" })
            Assert.DoesNotContain(key, bareKeys);

        var onlyChannels = new DiagnosticsSources
        {
            RunDirectory = directory.Path,
            Snapshot = () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false),
            Channels = _ => Task.FromResult(new ChannelStateResult("{\"selected\":\"main\"}", null)),
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };
        var wired = JsonNode.Parse(await DiagnosticsCollector.CollectAsync(onlyChannels))!.AsObject();
        Assert.Contains("channels", wired.Select(pair => pair.Key));
        Assert.Contains("channels_error", wired.Select(pair => pair.Key));
        Assert.DoesNotContain("node_reach", wired.Select(pair => pair.Key));
    }

    [Fact]
    public async Task CollectorStartsProbesTogether()
    {
        using var directory = new TempDirectory();
        var entered = 0;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task WaitTogether()
        {
            if (Interlocked.Increment(ref entered) == 3) release.TrySetResult();
            await release.Task;
        }
        var sources = new DiagnosticsSources
        {
            RunDirectory = directory.Path,
            Snapshot = () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false),
            Channels = async _ => { await WaitTogether(); return new ChannelStateResult("{}", null); },
            NodeReach = async _ => { await WaitTogether(); return new ReachResult("{}", null); },
            Ipv6Reach = async _ => { await WaitTogether(); return new ReachResult("{}", null); },
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };
        var text = await DiagnosticsCollector.CollectAsync(sources).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(3, entered);
        Assert.NotNull(JsonNode.Parse(text));
    }

    [Fact]
    public async Task KernelLogLinesLoseColorCodes()
    {
        using var directory = new TempDirectory();
        var line = "\u001b[31mERROR\u001b[0m[0000] dial www.example.com";
        File.WriteAllText(Path.Combine(directory.Path, "sing-box.log"), line + "\n");
        File.WriteAllText(Path.Combine(directory.Path, "service.log"), line + "\n");
        var sources = new DiagnosticsSources
        {
            RunDirectory = directory.Path,
            Snapshot = () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false),
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };
        var root = JsonNode.Parse(await DiagnosticsCollector.CollectAsync(sources))!.AsObject();
        Assert.Equal("ERROR[0000] dial [域名]", root["logs"]!["sing-box.log"]!["lines"]![0]!.GetValue<string>());
        Assert.Contains("\u001b[31m", root["logs"]!["service.log"]!["lines"]![0]!.GetValue<string>());
        Assert.Equal("", DiagnosticsRedactor.StripColorCodes(null));
    }

    [Fact]
    public void NetworkScriptListsSecurityProducts()
    {
        var script = NetworkStateProbe.Script;
        Assert.Contains("root/SecurityCenter2", script);
        Assert.Contains("AntiVirusProduct", script);
        Assert.Contains("FirewallProduct", script);
        Assert.Contains("security_products", script);
        foreach (var word in new[] { "Set-", "New-", "Remove-", "Enable-", "Disable-", "Stop-", "Restart-", "Add-", "Clear-" })
            Assert.DoesNotContain(word, script);
    }

    [Fact]
    public void SourcesCarryChannelProbesOnlyWhenGiven()
    {
        using var directory = new TempDirectory();
        var without = ClientRuntime.DiagnosticsSourcesFor(directory.Path,
            () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false), false, null,
            new StubRunner(), new StubAdapters(), () => null, () => null);
        Assert.Null(without.Channels);
        Assert.Null(without.NodeReach);
        Assert.Null(without.Ipv6Reach);

        var channels = new Func<CancellationToken, Task<ChannelStateResult>>(_ => Task.FromResult(new ChannelStateResult("{}", null)));
        var nodeReach = new Func<CancellationToken, Task<ReachResult>>(_ => Task.FromResult(new ReachResult("{}", null)));
        var ipv6Reach = new Func<CancellationToken, Task<ReachResult>>(_ => Task.FromResult(new ReachResult("{}", null)));
        var with = ClientRuntime.DiagnosticsSourcesFor(directory.Path,
            () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false), true, null,
            new StubRunner(), new StubAdapters(), () => null, () => null, channels, nodeReach, ipv6Reach);
        Assert.Same(channels, with.Channels);
        Assert.Same(nodeReach, with.NodeReach);
        Assert.Same(ipv6Reach, with.Ipv6Reach);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> behavior) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return await behavior(request, cancellationToken);
        }
    }

    private sealed class QuietLauncher : ISingBoxLauncher
    {
        public ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit) => new IdleProcess();
    }

    private sealed class IdleProcess : ISingBoxProcess
    {
        public void Stop() { }
        public void Dispose() { }
    }

    private sealed class FakeKernelTable : IKernelProcessTable
    {
        public IReadOnlyList<KernelProcessInfo> FindByName(string processName) => [];
        public bool Kill(int id, TimeSpan wait) => true;
    }

    private sealed class StubRunner : ICommandRunner
    {
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default) =>
            Task.FromResult(new CommandResult(0, "{}"));
    }

    private sealed class StubAdapters : IAdapterProbe
    {
        public IReadOnlyList<AdapterInfo>? Snapshot() => [];
    }
}
