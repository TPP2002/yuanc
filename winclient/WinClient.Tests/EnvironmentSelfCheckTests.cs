using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Firewall;
using WinClient.Core.Pairing;
using WinClient.Core.Client;
using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class EnvironmentSelfCheckTests
{
    [Fact]
    public void 未取得浏览器信息时无法核验()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { BrowsersAtApply = null });
        Assert.Equal("browser_closed", report.Items[9].Id);
        Assert.Equal("无法核验", report.Items[9].Result);
        Assert.Equal("未取得浏览器进程信息", report.Items[9].Detail);
        Assert.Equal("9 项通过,1 项未能检查", report.Summary);
    }

    [Fact]
    public void 套用时没有浏览器运行则通过()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { BrowsersAtApply = [] });
        Assert.Equal("通过", report.Items[9].Result);
        Assert.Equal("套用环境时 Chrome / Edge 未运行", report.Items[9].Detail);
        Assert.Equal("10 项通过", report.Summary);
    }

    [Fact]
    public void 套用时浏览器仍在运行则提示重连()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { BrowsersAtApply = ["Chrome"] });
        Assert.Equal("未通过", report.Items[9].Result);
        Assert.Contains("Chrome", report.Items[9].Detail);
        Assert.Contains("关闭浏览器后重新连接一次即可通过", report.Items[9].Detail);
        Assert.Equal("1 项未通过:浏览器在环境切换前已关闭", report.Summary);
    }

    [Fact]
    public void 总开关关闭则跳过浏览器检查()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { EnvironmentEnabled = false, BrowsersAtApply = ["Chrome"] });
        Assert.Equal("跳过", report.Items[9].Result);
        Assert.Equal("环境一致性未启用", report.Items[9].Detail);
        Assert.Equal("5 项通过,5 项未能检查", report.Summary);
    }

    [Fact]
    public void 未取得网卡清单时无法核验()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Adapters = null });
        Assert.Equal("tun_subnet", report.Items[8].Id);
        Assert.Equal("无法核验", report.Items[8].Result);
        Assert.Equal("未取得本机网卡清单", report.Items[8].Detail);
        Assert.Equal("9 项通过,1 项未能检查", report.Summary);
    }

    [Fact]
    public void 重叠网段点名占用网卡()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with
        {
            Adapters = [.. Good.Adapters!, new("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", [new("172.19.0.1", 16)])]
        });
        Assert.Equal("未通过", report.Items[8].Result);
        Assert.Contains("vEthernet (WSL)", report.Items[8].Detail);
        Assert.Contains("172.19.0.1/16", report.Items[8].Detail);
        Assert.Equal("1 项未通过:虚拟网卡网段", report.Summary);
    }

    [Fact]
    public void 不冲突时只提醒虚拟网卡()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with
        {
            Adapters = [.. Good.Adapters!,
                new("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", [new("172.28.112.1", 20)]),
                new("以太网", "物理网卡", [new("192.168.1.8", 24)])]
        });
        Assert.Equal("通过", report.Items[8].Result);
        Assert.Contains("目前不冲突", report.Items[8].Detail);
        Assert.Contains("vEthernet (Default Switch)", report.Items[8].Detail);
        Assert.DoesNotContain("以太网", report.Items[8].Detail);
    }

    [Fact]
    public void 隧道自身不算占用也不提醒()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good);
        Assert.Equal("通过", report.Items[8].Result);
        Assert.Equal("隧道网段未被其他网卡占用", report.Items[8].Detail);
        Assert.DoesNotContain("本机有虚拟网卡", report.Items[8].Detail);
    }

    [Fact]
    public void 无效地址跳过且不抛异常()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Adapters = [new("网卡", "", [new("bad", 24)])] });
        Assert.Equal("通过", report.Items[8].Result);
    }

    [Theory]
    [InlineData("172.19.0.3", 32, "未通过")]
    [InlineData("172.19.0.4", 32, "通过")]
    [InlineData("172.18.0.1", 15, "未通过")]
    [InlineData("192.168.1.1", 0, "未通过")]
    public void 按较短前缀判定重叠且不受模式和总开关影响(string address, int prefix, string result)
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with
        {
            EnvironmentEnabled = false, Routing = RoutingTests.Apps,
            Adapters = [new("物理网卡", "", [new(address, prefix)])]
        });
        Assert.Equal(result, report.Items[8].Result);
    }
    private static SelfCheckInput AuthInput()
    {
        var auth = new AuthEndpoint(IPAddress.Parse("192.0.2.5"), 8080, RoutingTests.Service);
        return Good with { Auth = auth, ServiceProcessPath = RoutingTests.Service,
            SingboxConfig = RoutingRenderer.Render(LocalConfigRenderer.Render(TestData.Node()), RoutingPolicy.Global, RoutingTests.Service, auth) };
    }

    [Fact]
    public void GlobalAuthDirectRuleIsTheOnlyAllowedDirectPath()
    {
        var report = EnvironmentSelfCheck.Evaluate(AuthInput());
        Assert.Equal("通过", report.Items[6].Result);
        Assert.Equal("符合目标要求", report.Items[6].Detail);
        Assert.Equal("10 项通过", report.Summary);
    }

    [Fact]
    public void DirectWithoutAuthEndpointFails()
    {
        var report = EnvironmentSelfCheck.Evaluate(AuthInput() with { Auth = null });
        Assert.Equal("未通过", report.Items[6].Result);
        Assert.Contains("outbounds", report.Items[6].Detail);
    }

    [Fact]
    public void AuthDirectRuleMustBeFullyScoped()
    {
        var input = AuthInput();
        var config = JsonNode.Parse(input.SingboxConfig.GetRawText())!;
        config["route"]!["rules"]![0]!.AsObject().Remove("port");
        var report = EnvironmentSelfCheck.Evaluate(input with { SingboxConfig = JsonSerializer.SerializeToElement(config) });
        Assert.Equal("未通过", report.Items[6].Result);
        Assert.Contains("outbounds", report.Items[6].Detail);
    }

    [Fact]
    public void AppsChecksScopedRoutesAndSkipsWholeMachineIpv6()
    {
        var config = RoutingRenderer.Render(Good.SingboxConfig, RoutingTests.Apps, RoutingTests.Service);
        var report = EnvironmentSelfCheck.Evaluate(Good with { Routing = RoutingTests.Apps, SingboxConfig = config, Ipv6Reachable = null });
        Assert.Equal("通过", report.Items[6].Result); Assert.StartsWith("仅指定程序模式:", report.Items[6].Detail);
        Assert.Equal("跳过", report.Items[7].Result);
        Assert.Equal("9 项通过,1 项未能检查", report.Summary);
        var original = EnvironmentSelfCheck.Evaluate(Good with { Routing = RoutingTests.Apps });
        Assert.Equal("未通过", original.Items[6].Result); Assert.Contains("指定程序→proxy", original.Items[6].Detail);
        var bad = JsonSerializer.Deserialize<JsonElement>(config.GetRawText().Replace("\"detour\":\"proxy\"", "\"detour\":\"direct\""));
        report = EnvironmentSelfCheck.Evaluate(Good with { Routing = RoutingTests.Apps, SingboxConfig = bad });
        Assert.Equal("未通过", report.Items[6].Result); Assert.Contains("dns.servers", report.Items[6].Detail);
    }
    internal const string GoodConfig = """
        {"inbounds":[{"type":"tun"}],"route":{"final":"proxy","rules":[{"ip_version":6,"outbound":"block"}]},
         "dns":{"servers":[{"detour":"proxy"}]},"outbounds":[{"type":"vless","tag":"proxy"}]}
        """;
    internal static EnvironmentInspection GoodInspection => new("AUS Eastern Standard Time", 4,
        new Dictionary<string, string?> { ["WebRtcIPHandling"] = "default_public_interface_only", ["DefaultGeolocationSetting"] = "2", ["DnsOverHttpsMode"] = "secure", ["DnsOverHttpsTemplates"] = "https://1.1.1.1/dns-query" },
        new Dictionary<string, string?> { ["DefinePreferredLanguages"] = "en-AU,en", ["WebRtcLocalhostIpHandling"] = "default_public_interface_only", ["DefaultGeolocationSetting"] = "2", ["DnsOverHttpsMode"] = "secure", ["DnsOverHttpsTemplates"] = "https://1.1.1.1/dns-query" },
        ["en-AU", "en"]);
    private static SelfCheckInput Good => new(new(IPAddress.Parse("192.0.2.5"), "AU"), "192.0.2.5", "AU",
        true, true, EnvironmentSettingsStore.Default.Target, GoodInspection, false,
        JsonSerializer.Deserialize<JsonElement>(GoodConfig), DateTimeOffset.Parse("2026-10-22T00:00:00Z"))
        { BrowsersAtApply = [], Adapters = [new AdapterInfo(KillSwitchPlanner.TunAlias, "Wintun Userspace Tunnel", [new("172.19.0.1", 30)])] };

    [Fact]
    public void DohPolicyMismatchNamesOnlyTheValueName()
    {
        var inspection = GoodInspection;
        var chrome = inspection.Chrome.ToDictionary(pair => pair.Key, pair => pair.Value);
        var edge = inspection.Edge.ToDictionary(pair => pair.Key, pair => pair.Value);
        chrome["DnsOverHttpsMode"] = "automatic";
        edge["DnsOverHttpsTemplates"] = "https://resolver.example/dns-query";
        var report = EnvironmentSelfCheck.Evaluate(Good with { Inspection = inspection with { Chrome = chrome, Edge = edge } });
        Assert.Equal("未通过", report.Items[4].Result);
        Assert.Contains("DnsOverHttpsMode", report.Items[4].Detail);
        Assert.DoesNotContain("automatic", report.Items[4].Detail);
        Assert.Equal("未通过", report.Items[5].Result);
        Assert.Contains("DnsOverHttpsTemplates", report.Items[5].Detail);
        Assert.DoesNotContain("https://resolver.example/dns-query", report.Items[5].Detail);
        Assert.All(report.Items.Where((_, index) => index != 4 && index != 5), item => Assert.Equal("通过", item.Result));
    }

    [Fact]
    public void ReportWritesAtomicallyWithContractFieldsAndNoAddress()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "selfcheck.json");
        ClientRuntime.WriteSelfCheck(path, EnvironmentSelfCheck.Evaluate(Good));
        using (var json = JsonDocument.Parse(File.ReadAllText(path)))
        {
            Assert.Equal(Good.Now, json.RootElement.GetProperty("checked_at").GetDateTimeOffset());
            Assert.Equal("10 项通过", json.RootElement.GetProperty("summary").GetString());
            Assert.Equal(10, json.RootElement.GetProperty("items").GetArrayLength());
            Assert.Equal(new[] { "id", "name", "result", "detail" }, json.RootElement.GetProperty("items")[0].EnumerateObject().Select(x => x.Name));
        }
        Assert.False(File.Exists(path + ".tmp"));
        Assert.DoesNotContain("192.0.2.5", File.ReadAllText(path));
        ClientRuntime.WriteSelfCheck(path, EnvironmentSelfCheck.Evaluate(Good with { Ipv6Reachable = true }));
        using var replaced = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal("1 项未通过:IPv6 已封堵", replaced.RootElement.GetProperty("summary").GetString());
        // 用目录占据目标文件名，模拟写入失败，不修改任何真实系统设置。
        ClientRuntime.WriteSelfCheck(temp.Path, EnvironmentSelfCheck.Evaluate(Good));
        Assert.False(File.Exists(temp.Path + ".tmp"));
    }

    [Fact]
    public void AllEightPassInContractOrderWithoutExportingAddress()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good);
        Assert.Equal(new[] { "exit_country", "exit_node", "time_zone", "auto_time_zone", "chrome_policy", "edge_policy", "no_direct_path", "ipv6_direct", "tun_subnet", "browser_closed" }, report.Items.Select(x => x.Id));
        Assert.All(report.Items, item => Assert.Equal("通过", item.Result));
        Assert.Equal(10, report.Passed); Assert.Equal(0, report.Failed);
        Assert.Equal("10 项通过", report.Summary);
        Assert.Equal(Good.Now, report.CheckedAt);
        Assert.DoesNotContain("192.0.2.5", JsonSerializer.Serialize(report));
    }

    [Fact]
    public void 浏览器策略明细只在已核验结果中说明覆盖边界()
    {
        const string boundary = ";策略只覆盖 Chrome 与 Edge,360、QQ、搜狗、夸克等浏览器不受约束";
        var passed = EnvironmentSelfCheck.Evaluate(Good);
        var inspection = GoodInspection with { TimeZone = "China Standard Time", AutoTimeZoneStart = null,
            ChromeForcedLanguages = ["en", "en-AU"], Edge = new Dictionary<string, string?>() };
        var failed = EnvironmentSelfCheck.Evaluate(Good with { Inspection = inspection, EnvironmentApplied = false });
        var skipped = EnvironmentSelfCheck.Evaluate(Good with { EnvironmentEnabled = false });
        var unknown = EnvironmentSelfCheck.Evaluate(Good with { Inspection = null });

        foreach (var index in new[] { 4, 5 })
        {
            Assert.Equal("通过", passed.Items[index].Result);
            foreach (var name in new[] { "360", "夸克", "Chrome", "Edge" })
                Assert.Contains(name, passed.Items[index].Detail);
            Assert.EndsWith(boundary, passed.Items[index].Detail);
            Assert.Equal("未通过", failed.Items[index].Result);
            Assert.StartsWith("不符项:", failed.Items[index].Detail);
            Assert.EndsWith(boundary, failed.Items[index].Detail);
            Assert.DoesNotContain("en-AU", failed.Items[index].Detail);
            Assert.Equal("跳过", skipped.Items[index].Result);
            Assert.DoesNotContain("360", skipped.Items[index].Detail);
            Assert.Equal("无法核验", unknown.Items[index].Result);
            Assert.DoesNotContain("360", unknown.Items[index].Detail);
        }
        Assert.Contains("ForcedLanguages", failed.Items[4].Detail);
        foreach (var name in new[] { "DefinePreferredLanguages", "WebRtcLocalhostIpHandling", "DefaultGeolocationSetting" })
            Assert.Contains(name, failed.Items[5].Detail);
    }

    [Fact]
    public void CountryMismatchNamesFailureWithoutAddress()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Exit = new(Good.Exit!.Address, "CN") });
        Assert.Equal("未通过", report.Items[0].Result);
        Assert.Contains("CN", report.Items[0].Detail);
        Assert.Equal("1 项未通过:出口归属澳洲", report.Summary);
    }

    [Fact]
    public void DisabledEnvironmentSkipsFourChecks()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { EnvironmentEnabled = false, Inspection = null });
        Assert.All(report.Items.Skip(2).Take(4), item => { Assert.Equal("跳过", item.Result); Assert.Equal("环境一致性未启用", item.Detail); });
        Assert.Equal("5 项通过,5 项未能检查", report.Summary);
    }

    [Fact]
    public void MissingInspectionCannotVerifyEvenWhenApplyPreviouslySucceeded()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Inspection = null });
        Assert.All(report.Items.Skip(2).Take(4), item => Assert.Equal("无法核验", item.Result));
        Assert.Equal("6 项通过,4 项未能检查", report.Summary);
    }

    [Fact]
    public void MissingExitCountryAndIpv6AreUnknown()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Exit = null, Ipv6Reachable = null });
        Assert.Equal("无法核验", report.Items[0].Result);
        Assert.Equal("无法核验", report.Items[1].Result);
        Assert.Equal("无法核验", report.Items[7].Result);
        report = EnvironmentSelfCheck.Evaluate(Good with { Exit = new(Good.Exit!.Address, null) });
        Assert.Equal("探测点未返回国家码", report.Items[0].Detail);
    }

    [Fact]
    public void Ipv6DirectReachabilityFails()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Ipv6Reachable = true });
        Assert.Equal("未通过", report.Items[7].Result);
        Assert.Equal("IPv6 可直连,可能泄漏", report.Items[7].Detail);
        Assert.Equal("1 项未通过:IPv6 已封堵", report.Summary);
    }

    [Theory]
    [InlineData("\"type\":\"vless\"", "\"type\":\"direct\"", "outbounds")]
    [InlineData("\"detour\":\"proxy\"", "\"detour\":\"direct\"", "dns.servers")]
    [InlineData("\"ip_version\":6", "\"ip_version\":4", "route.rules")]
    [InlineData("\"final\":\"proxy\"", "\"final\":\"direct\"", "route.final")]
    public void UnsafeConfigurationListsMissingCondition(string before, string after, string field)
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { SingboxConfig = JsonSerializer.Deserialize<JsonElement>(GoodConfig.Replace(before, after)) });
        Assert.Equal("未通过", report.Items[6].Result);
        Assert.Contains(field, report.Items[6].Detail);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("{\"route\":[],\"dns\":false,\"outbounds\":{}}")]
    public void MissingConfigurationFailsWithoutThrowing(string json)
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { SingboxConfig = JsonSerializer.Deserialize<JsonElement>(json) });
        Assert.Equal("未通过", report.Items[6].Result);
        foreach (var field in new[] { "route.final", "route.rules", "dns.servers", "outbounds" }) Assert.Contains(field, report.Items[6].Detail);
    }

    [Fact]
    public void PolicyMismatchOnlyNamesValuesAndResultsUseFourLiterals()
    {
        var inspection = GoodInspection with { TimeZone = "China Standard Time", AutoTimeZoneStart = null,
            ChromeForcedLanguages = ["en", "en-AU"], Edge = new Dictionary<string, string?>() };
        var report = EnvironmentSelfCheck.Evaluate(Good with { Inspection = inspection, EnvironmentApplied = false });
        Assert.Contains("China Standard Time", report.Items[2].Detail);
        Assert.Equal("无法核验", report.Items[3].Result);
        Assert.Equal("未通过", report.Items[4].Result);
        Assert.Contains("ForcedLanguages", report.Items[4].Detail);
        Assert.DoesNotContain("en-AU", report.Items[4].Detail);
        Assert.Contains("DefinePreferredLanguages", report.Items[5].Detail);
        Assert.Contains("WebRtcLocalhostIpHandling", report.Items[5].Detail);
        Assert.Contains("DefaultGeolocationSetting", report.Items[5].Detail);
        Assert.All(report.Items, item => Assert.Contains(item.Result, new[] { "通过", "未通过", "跳过", "无法核验" }));
    }

    [Theory]
    [InlineData("ip=1.2.3.4\nloc=AU", "AU")]
    [InlineData("loc=AU\r\nip=1.2.3.4\r\n", "AU")]
    [InlineData("ip=1.2.3.4\nloc=au", null)]
    [InlineData("ip=1.2.3.4\nloc=AUS", null)]
    public void TraceParserValidatesCountry(string body, string? country)
    {
        var result = HttpExitProbe.Parse(body);
        Assert.NotNull(result); Assert.Equal(IPAddress.Parse("1.2.3.4"), result.Address); Assert.Equal(country, result.Country);
    }

    [Theory]
    [InlineData("loc=AU")]
    [InlineData("ip=bad\nloc=AU")]
    public void TraceWithoutValidIpIsUnknown(string body) => Assert.Null(HttpExitProbe.Parse(body));
}
