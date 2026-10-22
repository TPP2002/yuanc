using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using WinClient.Core.Client;

namespace WinClient.Core.EnvironmentSupport;

public sealed record CheckItem(string Id, string Name, string Result, string Detail);

public sealed record EnvironmentReport(DateTimeOffset CheckedAt, IReadOnlyList<CheckItem> Items)
{
    public int Passed => Items.Count(item => item.Result == "通过");
    public int Failed => Items.Count(item => item.Result == "未通过");
    public string Summary => Failed > 0
        ? $"{Failed} 项未通过:" + string.Join("、", Items.Where(item => item.Result == "未通过").Select(item => item.Name))
        : Passed > 0
            ? $"{Passed} 项通过" + (Items.Count > Passed ? $",{Items.Count - Passed} 项未能检查" : "")
            : $"{Items.Count} 项未能检查";
}

public sealed record SelfCheckInput(ExitProbeResult? Exit, string NodeHost, string ExpectedCountry,
    bool EnvironmentEnabled, bool EnvironmentApplied, EnvironmentTarget Target, EnvironmentInspection? Inspection,
    bool? Ipv6Reachable, JsonElement SingboxConfig, DateTimeOffset Now);

public interface IIpv6Probe
{
    Task<bool> CanReachAsync(CancellationToken token);
}

public sealed class SocketIpv6Probe : IIpv6Probe
{
    public async Task<bool> CanReachAsync(CancellationToken token)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 443), timeout.Token).ConfigureAwait(false);
            return true;
        }
        catch (Exception) { return false; }
    }
}

/// <summary>只评估输入，不修改系统、连接或断网保护；报告不包含出口地址。</summary>
public static class EnvironmentSelfCheck
{
    public static EnvironmentReport Evaluate(SelfCheckInput input)
    {
        var items = new List<CheckItem>(8);
        void Add(string id, string name, bool pass, string detail) => items.Add(new(id, name, pass ? "通过" : "未通过", detail));
        if (input.Exit is null)
            items.Add(new("exit_country", "出口归属澳洲", "无法核验", "未取得出口探测结果"));
        else if (input.Exit.Country is null)
            items.Add(new("exit_country", "出口归属澳洲", "无法核验", "探测点未返回国家码"));
        else Add("exit_country", "出口归属澳洲", input.Exit.Country == input.ExpectedCountry, "探测点国家码:" + input.Exit.Country);

        if (input.Exit is null)
            items.Add(new("exit_node", "出口与节点一致", "无法核验", "未取得出口探测结果"));
        else
        {
            var matches = IPAddress.TryParse(input.NodeHost, out var node) && input.Exit.Address.Equals(node);
            Add("exit_node", "出口与节点一致", matches, matches ? "出口与配置节点地址一致" : "出口与配置节点地址不一致");
        }

        void Inspect(string id, string name, Func<EnvironmentInspection, CheckItem> evaluate)
        {
            items.Add(!input.EnvironmentEnabled ? new(id, name, "跳过", "环境一致性未启用")
                : input.Inspection is null ? new(id, name, "无法核验", "未取得环境巡查结果") : evaluate(input.Inspection));
        }
        Inspect("time_zone", "系统时区", inspection => new("time_zone", "系统时区",
            inspection.TimeZone == input.Target.TimeZoneId ? "通过" : "未通过", "当前时区:" + inspection.TimeZone));
        Inspect("auto_time_zone", "自动时区已关", inspection => new("auto_time_zone", "自动时区已关",
            inspection.AutoTimeZoneStart is null ? "无法核验" : inspection.AutoTimeZoneStart == 4 ? "通过" : "未通过",
            inspection.AutoTimeZoneStart is null ? "未取得自动时区服务启动值" : inspection.AutoTimeZoneStart == 4 ? "自动时区已关闭" : "自动时区未关闭"));
        Inspect("chrome_policy", "Chrome 策略", inspection => Policy("chrome_policy", "Chrome 策略",
            ("ForcedLanguages", inspection.ChromeForcedLanguages.SequenceEqual(input.Target.Languages, StringComparer.Ordinal)),
            ("WebRtcIPHandling", Value(inspection.Chrome, "WebRtcIPHandling") == "default_public_interface_only"),
            ("DefaultGeolocationSetting", Value(inspection.Chrome, "DefaultGeolocationSetting") == "2")));
        Inspect("edge_policy", "Edge 策略", inspection => Policy("edge_policy", "Edge 策略",
            ("DefinePreferredLanguages", Value(inspection.Edge, "DefinePreferredLanguages") == string.Join(",", input.Target.Languages)),
            ("WebRtcLocalhostIpHandling", Value(inspection.Edge, "WebRtcLocalhostIpHandling") == "default_public_interface_only"),
            ("DefaultGeolocationSetting", Value(inspection.Edge, "DefaultGeolocationSetting") == "2")));

        var config = input.SingboxConfig;
        var route = Property(config, "route");
        var rules = Property(route, "rules");
        var servers = Property(Property(config, "dns"), "servers");
        var outbounds = Property(config, "outbounds");
        items.Add(Policy("no_direct_path", "配置无直连路径",
            ("route.final", Text(Property(route, "final")) == "proxy"),
            ("route.rules IPv6 阻断", rules.ValueKind == JsonValueKind.Array && rules.EnumerateArray().Any(rule =>
                Property(rule, "ip_version") is var version && version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out var number)
                && number == 6 && Text(Property(rule, "outbound")) == "block")),
            ("dns.servers detour", servers.ValueKind == JsonValueKind.Array && servers.EnumerateArray().All(server => Text(Property(server, "detour")) == "proxy")),
            ("outbounds 无 direct", outbounds.ValueKind == JsonValueKind.Array && outbounds.EnumerateArray().All(outbound => Text(Property(outbound, "type")) != "direct"))));
        items.Add(new("ipv6_direct", "IPv6 已封堵", input.Ipv6Reachable is null ? "无法核验" : input.Ipv6Reachable.Value ? "未通过" : "通过",
            input.Ipv6Reachable is null ? "未取得 IPv6 探测结果" : input.Ipv6Reachable.Value ? "IPv6 可直连,可能泄漏" : "固定 IPv6 地址未能建立连接"));
        return new(input.Now, items);
    }

    private static string? Value(IReadOnlyDictionary<string, string?> values, string key) => values.TryGetValue(key, out var value) ? value : null;
    private static JsonElement Property(JsonElement element, string key) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(key, out var value) ? value : default;
    private static string? Text(JsonElement element) => element.ValueKind == JsonValueKind.String ? element.GetString() : null;
    private static CheckItem Policy(string id, string name, params (string Name, bool Matches)[] conditions)
    {
        var missing = conditions.Where(condition => !condition.Matches).Select(condition => condition.Name).ToArray();
        return new(id, name, missing.Length == 0 ? "通过" : "未通过", missing.Length == 0 ? "符合目标要求" : "不符项:" + string.Join("、", missing));
    }
}
