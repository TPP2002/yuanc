using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Firewall;

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
    bool? Ipv6Reachable, JsonElement SingboxConfig, DateTimeOffset Now)
{
    public RoutingPolicy Routing { get; init; } = RoutingPolicy.Global;
    public AuthEndpoint? Auth { get; init; }
    public string? ServiceProcessPath { get; init; }
    public IReadOnlyList<AdapterInfo>? Adapters { get; init; }
    public IReadOnlyList<string>? BrowsersAtApply { get; init; }
}

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
    public const string TunSubnet = "172.19.0.0/30";
    internal static readonly string[] VirtualAdapterKeywords =
        ["vEthernet", "Hyper-V", "WSL", "Docker", "VMware", "VirtualBox", "Wi-Fi Direct", "Hosted Network"];

    public static EnvironmentReport Evaluate(SelfCheckInput input)
    {
        var items = new List<CheckItem>(10);
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
            ("DefaultGeolocationSetting", Value(inspection.Chrome, "DefaultGeolocationSetting") == "2"),
            PolicyValue(inspection.Chrome, "DnsOverHttpsMode", EnvironmentPlanner.DohMode),
            PolicyValue(inspection.Chrome, "DnsOverHttpsTemplates", EnvironmentPlanner.DohTemplate)));
        Inspect("edge_policy", "Edge 策略", inspection => Policy("edge_policy", "Edge 策略",
            ("DefinePreferredLanguages", Value(inspection.Edge, "DefinePreferredLanguages") == string.Join(",", input.Target.Languages)),
            ("WebRtcLocalhostIpHandling", Value(inspection.Edge, "WebRtcLocalhostIpHandling") == "default_public_interface_only"),
            ("DefaultGeolocationSetting", Value(inspection.Edge, "DefaultGeolocationSetting") == "2"),
            PolicyValue(inspection.Edge, "DnsOverHttpsMode", EnvironmentPlanner.DohMode),
            PolicyValue(inspection.Edge, "DnsOverHttpsTemplates", EnvironmentPlanner.DohTemplate)));

        var config = input.SingboxConfig;
        var route = Property(config, "route");
        var rules = Property(route, "rules");
        var servers = Property(Property(config, "dns"), "servers");
        var outbounds = Property(config, "outbounds");
        if (input.Routing.Mode == RoutingMode.Apps)
        {
            bool HasPrograms(JsonElement rule)
            {
                var patterns = Property(rule, "process_path_regex");
                return patterns.ValueKind == JsonValueKind.Array && input.Routing.Apps.All(path =>
                    patterns.EnumerateArray().Any(pattern => Text(pattern) == RoutingRenderer.PathPattern(path)));
            }
            bool HasRule(string outbound, bool ipv6) => rules.ValueKind == JsonValueKind.Array && rules.EnumerateArray().Any(rule =>
                HasPrograms(rule) && Text(Property(rule, "outbound")) == outbound && (!ipv6 ||
                    (Property(rule, "ip_version") is var version && version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out var number) && number == 6)));
            var scoped = Policy("no_direct_path", "配置无直连路径",
                ("route.final direct", Text(Property(route, "final")) == "direct"),
                ("route.rules 指定程序→proxy", HasRule("proxy", false)),
                ("route.rules 指定程序 IPv6 阻断", HasRule("block", true)),
                ("dns.servers detour", servers.ValueKind == JsonValueKind.Array && servers.EnumerateArray().All(server => Text(Property(server, "detour")) == "proxy")));
            items.Add(scoped with { Detail = "仅指定程序模式:" + scoped.Detail });
            items.Add(new("ipv6_direct", "IPv6 已封堵", "跳过", "仅指定程序模式不检测整机 IPv6;指定程序的 IPv6 已由配置与防火墙阻断"));
        }
        else
        {
        items.Add(Policy("no_direct_path", "配置无直连路径",
            ("route.final", Text(Property(route, "final")) == "proxy"),
            ("route.rules IPv6 阻断", rules.ValueKind == JsonValueKind.Array && rules.EnumerateArray().Any(rule =>
                Property(rule, "ip_version") is var version && version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out var number)
                && number == 6 && Text(Property(rule, "outbound")) == "block")),
            ("dns.servers detour", servers.ValueKind == JsonValueKind.Array && servers.EnumerateArray().All(server => Text(Property(server, "detour")) == "proxy")),
            ("outbounds direct 只限后台服务到鉴权端口", DirectOnlyForAuth(outbounds, rules, input.Auth, input.ServiceProcessPath))));
        items.Add(new("ipv6_direct", "IPv6 已封堵", input.Ipv6Reachable is null ? "无法核验" : input.Ipv6Reachable.Value ? "未通过" : "通过",
            input.Ipv6Reachable is null ? "未取得 IPv6 探测结果" : input.Ipv6Reachable.Value ? "IPv6 可直连,可能泄漏" : "固定 IPv6 地址未能建立连接"));
        }
        items.Add(CheckTunSubnet(input.Adapters));
        items.Add(CheckBrowsersClosed(input));
        return new(input.Now, items);
    }

    private static CheckItem CheckBrowsersClosed(SelfCheckInput input)
    {
        const string id = "browser_closed";
        const string name = "浏览器在环境切换前已关闭";
        if (!input.EnvironmentEnabled) return new(id, name, "跳过", "环境一致性未启用");
        var list = input.BrowsersAtApply;
        if (list is null) return new(id, name, "无法核验", "未取得浏览器进程信息");
        if (list.Count == 0) return new(id, name, "通过", "套用环境时 Chrome / Edge 未运行");
        return new(id, name, "未通过", $"套用环境时 {string.Join("、", list)} 仍在运行,已打开的网页可能还带着切换前的时区;关闭浏览器后重新连接一次即可通过");
    }

    private static CheckItem CheckTunSubnet(IReadOnlyList<AdapterInfo>? adapters)
    {
        if (adapters is null) return new("tun_subnet", "虚拟网卡网段", "无法核验", "未取得本机网卡清单");
        var others = adapters.Where(adapter => adapter.Name != KillSwitchPlanner.TunAlias).ToArray();
        var conflicts = others.SelectMany(adapter => adapter.Ipv4
            .Where(OverlapsTunSubnet).Select(address => $"{adapter.Name}({address.Address}/{address.PrefixLength})")).ToArray();
        if (conflicts.Length > 0)
            return new("tun_subnet", "虚拟网卡网段", "未通过",
                TunSubnet + " 被占用:" + string.Join("、", conflicts) + ";请关闭该虚拟网卡、热点或虚拟机后重新连接");

        var detail = "隧道网段未被其他网卡占用";
        var virtualNames = others.Where(adapter => VirtualAdapterKeywords.Any(keyword =>
            adapter.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
            adapter.Description.Contains(keyword, StringComparison.OrdinalIgnoreCase))).Select(adapter => adapter.Name).ToArray();
        if (virtualNames.Length > 0)
            detail += ";本机有虚拟网卡:" + string.Join("、", virtualNames) + ",目前不冲突,它们重启后可能换到 172.16.0.0/12 里的其他网段";
        return new("tun_subnet", "虚拟网卡网段", "通过", detail);
    }

    private static bool OverlapsTunSubnet(AdapterAddress address)
    {
        if (address.PrefixLength is < 0 or > 32 || !IPAddress.TryParse(address.Address, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = ip.GetAddressBytes();
        var number = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        var prefix = Math.Min(address.PrefixLength, 30);
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        const uint tunNetwork = (172u << 24) | (19u << 16);
        return (number & mask) == (tunNetwork & mask);
    }

    private static bool DirectOnlyForAuth(JsonElement outbounds, JsonElement rules, AuthEndpoint? auth, string? serviceProcessPath)
    {
        if (outbounds.ValueKind != JsonValueKind.Array || rules.ValueKind != JsonValueKind.Array) return false;
        var directOutbounds = outbounds.EnumerateArray().Where(value => Text(Property(value, "type")) == "direct").ToArray();
        var directRules = rules.EnumerateArray().Where(value => Text(Property(value, "outbound")) == "direct").ToArray();
        if (directOutbounds.Length == 0 && directRules.Length == 0) return true;
        if (auth is null || string.IsNullOrEmpty(serviceProcessPath)) return false;
        bool SingleString(JsonElement rule, string key, string expected)
        {
            var values = Property(rule, key);
            return values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 1 && Text(values[0]) == expected;
        }
        return directOutbounds.All(value => Text(Property(value, "tag")) == "direct") && directRules.Length > 0
            && directRules.All(rule => SingleString(rule, "process_path_regex", RoutingRenderer.PathPattern(serviceProcessPath))
                && SingleString(rule, "ip_cidr", auth.Address + "/32")
                && Property(rule, "port") is var ports && ports.ValueKind == JsonValueKind.Array && ports.GetArrayLength() == 1
                && ports[0].ValueKind == JsonValueKind.Number && ports[0].TryGetInt32(out var port) && port == auth.Port);
    }

    private static string? Value(IReadOnlyDictionary<string, string?> values, string key) => values.TryGetValue(key, out var value) ? value : null;
    private static (string Name, bool Matches) PolicyValue(IReadOnlyDictionary<string, string?> values, string name, string expected)
        => (name, Value(values, name) == expected);
    private static JsonElement Property(JsonElement element, string key) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(key, out var value) ? value : default;
    private static string? Text(JsonElement element) => element.ValueKind == JsonValueKind.String ? element.GetString() : null;
    private static CheckItem Policy(string id, string name, params (string Name, bool Matches)[] conditions)
    {
        var missing = conditions.Where(condition => !condition.Matches).Select(condition => condition.Name).ToArray();
        var detail = missing.Length == 0 ? "符合目标要求" : "不符项:" + string.Join("、", missing);
        if (id is "chrome_policy" or "edge_policy")
            detail += ";策略只覆盖 Chrome 与 Edge,360、QQ、搜狗、夸克等浏览器不受约束";
        return new(id, name, missing.Length == 0 ? "通过" : "未通过", detail);
    }
}
