using System.Net;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class EnvironmentSelfCheckTests
{
    [Fact]
    public void AppsChecksScopedRoutesAndSkipsWholeMachineIpv6()
    {
        var config = RoutingRenderer.Render(Good.SingboxConfig, RoutingTests.Apps, RoutingTests.Service);
        var report = EnvironmentSelfCheck.Evaluate(Good with { Routing = RoutingTests.Apps, SingboxConfig = config, Ipv6Reachable = null });
        Assert.Equal("通过", report.Items[6].Result); Assert.StartsWith("仅指定程序模式:", report.Items[6].Detail);
        Assert.Equal("跳过", report.Items[7].Result);
        Assert.Equal("7 项通过,1 项未能检查", report.Summary);
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
        new Dictionary<string, string?> { ["WebRtcIPHandling"] = "default_public_interface_only", ["DefaultGeolocationSetting"] = "2" },
        new Dictionary<string, string?> { ["DefinePreferredLanguages"] = "en-AU,en", ["WebRtcLocalhostIpHandling"] = "default_public_interface_only", ["DefaultGeolocationSetting"] = "2" },
        ["en-AU", "en"]);
    private static SelfCheckInput Good => new(new(IPAddress.Parse("192.0.2.5"), "AU"), "192.0.2.5", "AU",
        true, true, EnvironmentSettingsStore.Default.Target, GoodInspection, false,
        JsonSerializer.Deserialize<JsonElement>(GoodConfig), DateTimeOffset.Parse("2026-10-22T00:00:00Z"));

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
            Assert.Equal("8 项通过", json.RootElement.GetProperty("summary").GetString());
            Assert.Equal(8, json.RootElement.GetProperty("items").GetArrayLength());
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
        Assert.Equal(new[] { "exit_country", "exit_node", "time_zone", "auto_time_zone", "chrome_policy", "edge_policy", "no_direct_path", "ipv6_direct" }, report.Items.Select(x => x.Id));
        Assert.All(report.Items, item => Assert.Equal("通过", item.Result));
        Assert.Equal(8, report.Passed); Assert.Equal(0, report.Failed);
        Assert.Equal("8 项通过", report.Summary);
        Assert.Equal(Good.Now, report.CheckedAt);
        Assert.DoesNotContain("192.0.2.5", JsonSerializer.Serialize(report));
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
        Assert.Equal("4 项通过,4 项未能检查", report.Summary);
    }

    [Fact]
    public void MissingInspectionCannotVerifyEvenWhenApplyPreviouslySucceeded()
    {
        var report = EnvironmentSelfCheck.Evaluate(Good with { Inspection = null });
        Assert.All(report.Items.Skip(2).Take(4), item => Assert.Equal("无法核验", item.Result));
        Assert.Equal("4 项通过,4 项未能检查", report.Summary);
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
