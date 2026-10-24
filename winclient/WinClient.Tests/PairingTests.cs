using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Auth;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Logging;
using WinClient.Core.Pairing;
using Xunit;

namespace WinClient.Tests;

public sealed class PairingTests
{
    [Theory]
    [InlineData("ycpair/2")]
    [InlineData("ycpair/3")]
    public void OptionalNodeEnvironmentFieldsAreParsedOrDefaultEmpty(string version)
    {
        var document = ValidDocument();
        document["format"] = version;
        var original = PairingFile.Parse(document.ToJsonString());
        Assert.Equal("", original.Node.TimeZone);
        Assert.Equal("", original.Node.Country);
        document["node"]!["time_zone"] = "Australia/Perth";
        document["node"]!["country"] = "AU";
        var pair = PairingFile.Parse(document.ToJsonString());
        Assert.Equal("Australia/Perth", pair.Node.TimeZone);
        Assert.Equal("AU", pair.Node.Country);
    }

    [Theory]
    [InlineData("time_zone", "\"bad;zone\"", "配对文件的时区标识格式不正确,请重新导出。")]
    [InlineData("time_zone", "42", "配对文件的时区标识格式不正确,请重新导出。")]
    [InlineData("time_zone", "null", "配对文件的时区标识格式不正确,请重新导出。")]
    [InlineData("time_zone", "\"\"", "配对文件的时区标识格式不正确,请重新导出。")]
    [InlineData("country", "\"au\"", "配对文件的国家码格式不正确,请重新导出。")]
    [InlineData("country", "42", "配对文件的国家码格式不正确,请重新导出。")]
    [InlineData("country", "null", "配对文件的国家码格式不正确,请重新导出。")]
    [InlineData("country", "\"\"", "配对文件的国家码格式不正确,请重新导出。")]
    public void InvalidNodeEnvironmentFieldsHaveSpecificErrors(string field, string value, string message)
    {
        var document = ValidDocument();
        document["node"]![field] = JsonNode.Parse(value);
        Assert.Equal(message, Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString())).Message);
    }

    internal static string GoldenDirectory
    {
        get
        {
            for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            {
                var path = Path.Combine(directory.FullName, "node", "tests", "golden", "proxy");
                if (File.Exists(Path.Combine(path, "client-windows.json"))) return path;
            }
            throw new FileNotFoundException("找不到节点仓黄金文件，禁止改用手抄的预期配置。");
        }
    }

    internal static JsonObject ValidDocument()
    {
        var input = JsonNode.Parse(File.ReadAllText(Path.Combine(GoldenDirectory, "inputs.json")))!;
        return new JsonObject
        {
            ["format"] = "ycpair/3", ["exported_at"] = "2026-10-22T00:00:00+00:00",
            ["node"] = new JsonObject
            {
                ["host"] = input["context"]!["server_host"]!.DeepClone(),
                ["reality_port"] = 443, ["hy2_port"] = 24443, ["sni"] = "www.microsoft.com",
                ["reality_public_key"] = input["context"]!["reality"]!["public_key"]!.DeepClone(),
                ["short_id"] = input["context"]!["reality"]!["short_id"]!.DeepClone(),
                ["uuid"] = input["device"]!["uuid"]!.DeepClone(),
                ["hy2_password"] = input["device"]!["hy2_password"]!.DeepClone(),
                ["hy2_server_name"] = input["context"]!["hy2_server_name"]!.DeepClone(),
                ["hy2_certificate"] = input["context"]!["hy2_certificate"]!.DeepClone(),
                ["hy2_obfs_password"] = input["context"]!["hy2_obfs_password"]!.DeepClone()
            }
        };
    }

    internal static PairingFile ValidPairing() => PairingFile.Parse(ValidDocument().ToJsonString());

    [Theory]
    [InlineData("format", "\"ycpair/4\"")]
    [InlineData("host", "\"node.invalid\"")]
    [InlineData("host", "\"::1\"")]
    [InlineData("host", "\"127.1\"")]
    [InlineData("host", "\"2130706433\"")]
    [InlineData("host", "\"203.0.113.999\"")]
    [InlineData("host", "null")]
    [InlineData("reality_port", "0")]
    [InlineData("reality_port", "65536")]
    [InlineData("hy2_port", "0")]
    [InlineData("hy2_port", "65536")]
    [InlineData("hy2_port", "\"24443\"")]
    [InlineData("reality_public_key", "\"short\"")]
    [InlineData("reality_public_key", "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+\"")]
    [InlineData("short_id", "\"x1\"")]
    [InlineData("short_id", "\"1\"")]
    [InlineData("short_id", "\"0123456789abcdef0\"")]
    [InlineData("uuid", "\"00000000-0000-1000-8000-000000000001\"")]
    [InlineData("uuid", "\"00000000-0000-4000-0000-000000000001\"")]
    [InlineData("uuid", "null")]
    [InlineData("hy2_password", "\"\"")]
    [InlineData("hy2_password", "null")]
    [InlineData("sni", "null")]
    public void RejectsEveryInvalidFieldWithChineseReason(string field, string value)
    {
        var document = ValidDocument();
        var target = field == "format" ? document : document["node"]!.AsObject();
        target[field] = JsonNode.Parse(value);
        var exception = Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        Assert.Matches("[\u4e00-\u9fff]", exception.Message);
        Assert.DoesNotContain(ValidPairing().Node.Hy2Password, exception.Message);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"format\":\"ycpair/1\",\"node\":null}")]
    [InlineData("{\"format\":\"ycpair/1\",\"node\":{}}")]
    public void RejectsMalformedOrMissingFields(string json) => Assert.Throws<InvalidDataException>(() => PairingFile.Parse(json));

    [Theory]
    [InlineData(1, "ab")]
    [InlineData(65535, "0123456789ABCDEF")]
    public void AcceptsBoundaryPortsAndShortIdentifiers(int port, string shortId)
    {
        var document = ValidDocument();
        document["node"]!["reality_port"] = port;
        document["node"]!["hy2_port"] = port;
        document["node"]!["short_id"] = shortId;
        var pairing = PairingFile.Parse(document.ToJsonString());
        var config = LocalConfigRenderer.Render(pairing.Node);
        Assert.Equal(port, config.GetProperty("outbounds")[0].GetProperty("server_port").GetInt32());
        Assert.Equal(port, config.GetProperty("outbounds")[1].GetProperty("server_port").GetInt32());
        var plan = KillSwitchPlanner.Plan([IPAddress.Parse(pairing.Node.Host)], KillSwitchPlanner.TunAlias,
            Path.GetFullPath("fake.exe"), port, KillSwitchMode.Apply, port);
        Assert.Equal(port.ToString(), plan.OfType<AddRule>().Single(r => r.Protocol == "TCP").RemotePort);
        Assert.Equal(port.ToString(), plan.OfType<AddRule>().Single(r => r.Name == KillSwitchPlanner.NodePrefix + "Udp").RemotePort);
        Assert.Equal(6, plan.OfType<AddRule>().Count());
    }

    [Fact]
    public void LocalConfigurationEqualsNodeGoldenFileAndTransportOnlyAddsInterfaceName()
    {
        var configuration = LocalConfigRenderer.Render(ValidPairing().Node);
        var actual = JsonNode.Parse(configuration.GetRawText())!.AsObject();
        // Same test-only envelope as node/tests/test_proxy_client_render.py; no configuration fields removed.
        actual["_comment"] = "测试向量,不是真凭据";
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(GoldenDirectory, "client-windows.json")));
        Assert.True(JsonNode.DeepEquals(expected, actual), "本地配置必须与节点黄金文件全部字段和值一致。");
        var rendered = JsonNode.Parse(TunnelTransport.RenderConfiguration(configuration).GetRawText())!;
        Assert.Equal(KillSwitchPlanner.TunAlias, rendered["inbounds"]![0]!["interface_name"]!.GetValue<string>());
        rendered["inbounds"]![0]!.AsObject().Remove("interface_name");
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(configuration.GetRawText()), rendered));
    }

    [Fact]
    public async Task PairingConnectRefreshAndDisconnectNeverCallHttp()
    {
        var calls = 0;
        using var http = new HttpClient(new AuthTests.Handler(_ =>
        { calls++; throw new InvalidOperationException("自用模式不得发出鉴权请求"); })) { BaseAddress = new("https://unit.invalid") };
        var auth = new AuthServerSessionSource(new AuthApiClient(http), new WinClient.Core.Storage.InMemoryCredentialStore());
        var order = new List<string>();
        using var controller = new ClientController(auth, new FakeFirewall(order), new FakeTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        var pairing = ValidPairing();
        await controller.ChangeSessionSourceAsync(() => new PairingSessionSource(pairing), "已导入配对文件，点击连接");
        Assert.Empty(order); // Import never connects automatically.
        await controller.ConnectAsync();
        Assert.Equal(WinClient.Core.State.ConnectionState.Connected, controller.Snapshot.State);
        await controller.RefreshSessionAsync();
        await controller.RedeemAsync("must-not-send");
        await controller.DisconnectAsync();
        Assert.Equal(0, calls);
        Assert.Contains("apply", order); Assert.Contains("start", order);
        Assert.Equal("remove", order.Last());
    }

    [Fact]
    public async Task LocalSessionHasFixedLifetimeAndRegistersAllThreeSecrets()
    {
        var pairing = ValidPairing(); var sink = new AuthTests.MemoryLog(); var log = new RedactingLog(sink);
        var source = new PairingSessionSource(pairing, log);
        var response = await source.GetSessionAsync();
        Assert.Equal(AuthResult.Ok, response.Result);
        Assert.Equal("", response.Value!.SessionToken);
        Assert.Equal(DateTimeOffset.MaxValue, response.Value.SessionExpiresAt);
        Assert.Equal(DateTimeOffset.MaxValue, response.Value.AccountExpiresAt);
        Assert.Same(pairing.Node, response.Value.Node);
        Assert.False(string.IsNullOrEmpty(pairing.Node.Hy2ObfsPassword));
        log.Write(pairing.Node.Uuid + " " + pairing.Node.Hy2Password + " " + pairing.Node.Hy2ObfsPassword);
        Assert.DoesNotContain(pairing.Node.Uuid, Assert.Single(sink.Lines));
        Assert.DoesNotContain(pairing.Node.Hy2Password, Assert.Single(sink.Lines));
        Assert.DoesNotContain(pairing.Node.Hy2ObfsPassword, Assert.Single(sink.Lines));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await source.GetSessionAsync(cancelled.Token));
    }

    [Fact]
    public void PairingStoreKeepsWholeDocumentEncryptedAndClears()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var directory = new TempDirectory(); var store = new PairingStore(directory.Path);
        var document = ValidDocument(); document["device_name"] = "家里的电脑"; document["extra"] = "keep-this-field";
        var pairing = PairingFile.Parse(document.ToJsonString());
        Assert.Null(store.Load()); store.Save(pairing);
        Assert.Equal(pairing.RawJson, store.Load()!.RawJson);
        Assert.Equal("家里的电脑", store.Load()!.DisplayName);
        var ciphertext = Encoding.UTF8.GetString(File.ReadAllBytes(store.FilePath));
        Assert.DoesNotContain(pairing.Node.Uuid, ciphertext);
        Assert.DoesNotContain(pairing.Node.Hy2Password, ciphertext);
        Assert.DoesNotContain(pairing.Node.Hy2ObfsPassword, ciphertext);
        Assert.DoesNotContain("ycpair/3", ciphertext);
        Assert.Equal(new[] { store.FilePath }, Directory.GetFiles(directory.Path, "*", SearchOption.AllDirectories));
        File.WriteAllText(store.FilePath, "corrupt");
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => store.Load());
        store.Clear(); store.Clear(); Assert.False(store.Exists); Assert.Null(store.Load());
    }

    [Fact]
    public void PairingTakesPriorityOverServerAndClearRestoresFallbackOrUnconfigured()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var directory = new TempDirectory(); var store = new PairingStore(directory.Path);
        var serverPath = Path.Combine(directory.Path, "server.json");
        File.WriteAllText(serverPath, JsonSerializer.Serialize(new { server_url = "https://192.0.2.1", server_spki_sha256 = Convert.ToBase64String(new byte[32]), sing_box_path = Path.Combine(directory.Path, "fake.exe") }));
        using var http = new HttpClient(new AuthTests.Handler(_ => throw new InvalidOperationException())) { BaseAddress = new("https://unit.invalid") };
        var server = new AuthServerSessionSource(new AuthApiClient(http), new WinClient.Core.Storage.InMemoryCredentialStore());
        var fallbackCalls = 0;
        ISessionSource? Fallback() { fallbackCalls++; return ClientSettings.Load(directory.Path, kernelRoot: directory.Path) is null ? null : server; }
        store.Save(ValidPairing());
        Assert.IsType<PairingSessionSource>(ClientRuntime.SelectSessionSource(store, Fallback));
        Assert.Equal(0, fallbackCalls);
        store.Clear();
        Assert.Same(server, ClientRuntime.SelectSessionSource(store, Fallback));
        File.Delete(serverPath);
        store.Save(ValidPairing()); store.Clear();
        Assert.Null(ClientRuntime.SelectSessionSource(store, Fallback));
        Assert.Equal(2, fallbackCalls);
    }

    [Fact]
    public async Task CannotReplacePairingWhileProtectionIsActiveAndClearUpdatesMode()
    {
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(ValidPairing()), new FakeFirewall(order), new FakeTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        var changed = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ChangeSessionSourceAsync(() => { changed = true; return null; }, ""));
        Assert.False(changed); Assert.Equal("自用模式", controller.Snapshot.Mode);
        Assert.DoesNotContain("remove", order);
        await controller.DisconnectAsync();
        await controller.ChangeSessionSourceAsync(() => null, "已清除配对文件");
        Assert.Equal("未配置", controller.Snapshot.Mode);
        await controller.ConnectAsync();
        Assert.Equal("未配置服务器", controller.Snapshot.Message);
        Assert.Equal(1, order.Count(x => x == "start"));
    }

    internal sealed class FakeFirewall(List<string> order) : IKillSwitch
    {
        public bool HasPendingState { get; set; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) { order.Add("apply"); return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) { order.Add("update"); return Task.CompletedTask; }
        public Task RemoveAsync() { order.Add("remove"); return Task.CompletedTask; }
        public Task<string?> RecoverAsync() { order.Add("recover"); return Task.FromResult<string?>(null); }
    }
    internal sealed class FakeTunnel(List<string> order, bool fail = false) : ITunnelTransport
    {
        public event EventHandler? TunnelDown { add { } remove { } }
        public Task StartAsync(JsonElement configuration, CancellationToken cancellationToken)
        { order.Add("start"); if (fail) throw new IOException("测试断线"); return Task.CompletedTask; }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }
}
