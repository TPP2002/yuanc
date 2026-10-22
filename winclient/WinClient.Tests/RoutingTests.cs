using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Pairing;
using Xunit;

namespace WinClient.Tests;

public sealed class RoutingTests
{
    internal const string Chrome = @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";
    internal const string Service = @"C:\Program Files\YuanC\WinClient.App.exe";
    internal static RoutingPolicy Apps => RoutingPolicy.Create("apps", [Chrome]);
    [Theory]
    [InlineData("bad", "C:\\app.exe", "代理范围只能是全部流量或仅指定程序。")]
    [InlineData("apps", "app.exe", "程序路径必须是以 .exe 结尾的完整路径。")]
    [InlineData("apps", "C:\\app.txt", "程序路径必须是以 .exe 结尾的完整路径。")]
    [InlineData("apps", "C:\\dir\\..\\app.exe", "程序路径必须是以 .exe 结尾的完整路径。")]
    [InlineData("apps", "C:\\dir/../app.exe", "程序路径必须是以 .exe 结尾的完整路径。")]
    [InlineData("apps", "C:\\a\nb.exe", "程序路径必须是以 .exe 结尾的完整路径。")]
    public void RejectsInvalidPolicy(string mode, string path, string message)
        => Assert.Equal(message, Assert.Throws<ArgumentException>(() => RoutingPolicy.Create(mode, [path])).Message);

    [Fact]
    public void TrimsDeduplicatesAndKeepsListInGlobalMode()
    {
        var policy = RoutingPolicy.Create("GLOBAL", [" " + Chrome + " ", Chrome.ToUpperInvariant()]);
        Assert.Equal(RoutingMode.Global, policy.Mode); Assert.Equal(Chrome, Assert.Single(policy.Apps));
        Assert.Equal(32, RoutingPolicy.Create("apps", Enumerable.Range(1, 32).Select(i => $@"C:\a{i}.exe")).Apps.Count);
        Assert.Equal("最多选择 32 个程序。", Assert.Throws<ArgumentException>(() =>
            RoutingPolicy.Create("apps", Enumerable.Range(1, 33).Select(i => $@"C:\a{i}.exe"))).Message);
        Assert.Throws<ArgumentException>(() => RoutingPolicy.Create("apps", [@"C:\" + new string('a', 254) + ".exe"]));
    }

    [Fact]
    public void StoreFallsBackAndWritesAtomically()
    {
        using var temp = new TempDirectory();
        var store = new RoutingSettingsStore(temp.Path);
        Assert.Equal(RoutingMode.Global, store.Read().Mode);
        var path = Path.Combine(temp.Path, "routing.json");
        foreach (var bad in new[] { "{bad", "{}", "{\"mode\":\"apps\",\"apps\":[\"relative.exe\"]}" })
        {
            File.WriteAllText(path, bad);
            Assert.Equal(RoutingMode.Global, store.Read().Mode); Assert.Empty(store.Read().Apps);
        }
        store.Write(Apps);
        Assert.Equal(Apps.Mode, store.Read().Mode); Assert.Equal(Apps.Apps, store.Read().Apps);
        Assert.False(File.Exists(path + ".tmp"));
        store.Write(RoutingPolicy.Create("global", [Chrome]));
        Assert.Equal(Chrome, Assert.Single(store.Read().Apps));
        Assert.False(File.Exists(path + ".tmp"));
    }

    [Fact]
    public void GlobalReturnsIdenticalBytes()
    {
        var input = LocalConfigRenderer.Render(TestData.Node());
        Assert.Equal(input.GetRawText(), RoutingRenderer.Render(input, RoutingPolicy.Global, Service).GetRawText());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AppsPreservesDnsAndInboundsAndOrdersRules(bool authenticated)
    {
        var input = LocalConfigRenderer.Render(TestData.Node());
        var auth = authenticated ? new AuthEndpoint(IPAddress.Parse("192.0.2.5"), 8080, Service) : null;
        var result = RoutingRenderer.Render(input, Apps, Service, auth);
        Assert.Equal(input.GetProperty("dns").GetRawText(), result.GetProperty("dns").GetRawText());
        Assert.Equal(input.GetProperty("inbounds").GetRawText(), result.GetProperty("inbounds").GetRawText());
        Assert.Equal(input.GetProperty("outbounds").GetArrayLength() + 1, result.GetProperty("outbounds").GetArrayLength());
        Assert.Equal("direct", result.GetProperty("route").GetProperty("final").GetString());
        Assert.True(result.GetProperty("route").GetProperty("auto_detect_interface").GetBoolean());
        var rules = result.GetProperty("route").GetProperty("rules").EnumerateArray().ToArray();
        Assert.Equal(authenticated ? 4 : 3, rules.Length);
        Assert.Equal("dns", rules[0].GetProperty("protocol").GetString());
        if (authenticated)
        {
            Assert.Equal("direct", rules[1].GetProperty("outbound").GetString());
            Assert.Equal("192.0.2.5/32", rules[1].GetProperty("ip_cidr")[0].GetString());
            Assert.Equal(8080, rules[1].GetProperty("port")[0].GetInt32());
            Assert.Equal(RoutingRenderer.PathPattern(Service), Assert.Single(rules[1].GetProperty("process_path_regex").EnumerateArray()).GetString());
        }
        Assert.Equal(6, rules[^2].GetProperty("ip_version").GetInt32());
        Assert.Equal("block", rules[^2].GetProperty("outbound").GetString());
        Assert.Equal("proxy", rules[^1].GetProperty("outbound").GetString());
        var expected = new[] { Chrome, Service }.Order(StringComparer.Ordinal).Select(RoutingRenderer.PathPattern);
        foreach (var rule in rules.TakeLast(2)) Assert.Equal(expected, rule.GetProperty("process_path_regex").EnumerateArray().Select(x => x.GetString()));
        Assert.DoesNotContain(rules, rule => rule.TryGetProperty("ip_version", out _) && !rule.TryGetProperty("process_path_regex", out _));
        var again = RoutingRenderer.Render(result, Apps, Service, auth);
        Assert.Equal(result.GetProperty("outbounds").GetArrayLength(), again.GetProperty("outbounds").GetArrayLength());
    }

    [Fact]
    public void PatternEscapesOnlyRe2Metacharacters()
    {
        const string path = @"C:\Program Files (x86)\a+b.exe";
        var pattern = RoutingRenderer.PathPattern(path);
        Assert.Equal(@"(?i)^C:\\Program Files \(x86\)\\a\+b\.exe$", pattern);
        Assert.DoesNotContain(@"\ ", pattern);
        Assert.Matches(pattern, path.ToUpperInvariant()); Assert.DoesNotMatch(pattern, path + "x");
    }

    [Fact]
    public void KeepsDnsWhitespaceAndDeduplicatesServicePath()
    {
        var raw = LocalConfigRenderer.Render(TestData.Node()).GetRawText().Replace("\"dns\":{", "\"dns\":{\n  ");
        var input = JsonSerializer.Deserialize<JsonElement>(raw);
        var policy = RoutingPolicy.Create("apps", [Chrome, Service, Service.ToUpperInvariant()]);
        var result = RoutingRenderer.Render(input, policy, Service);
        Assert.Equal(input.GetProperty("dns").GetRawText(), result.GetProperty("dns").GetRawText());
        Assert.Equal(2, result.GetProperty("route").GetProperty("rules")[2].GetProperty("process_path_regex").GetArrayLength());
    }

    [Theory]
    [InlineData("route")]
    [InlineData("dns")]
    [InlineData("outbounds")]
    [InlineData("detour")]
    public void RejectsMissingRequiredConfiguration(string field)
    {
        var json = JsonNode.Parse(LocalConfigRenderer.Render(TestData.Node()).GetRawText())!.AsObject();
        if (field == "detour") json["dns"]!["servers"]![0]!["detour"] = "direct";
        else json.Remove(field);
        var error = Assert.Throws<InvalidDataException>(() => RoutingRenderer.Render(JsonSerializer.SerializeToElement(json), Apps, Service));
        Assert.Contains("配置", error.Message);
        if (field == "detour") Assert.Equal("服务器配置缺少经隧道的 DNS,无法启用仅指定程序模式。", error.Message);
    }
}
