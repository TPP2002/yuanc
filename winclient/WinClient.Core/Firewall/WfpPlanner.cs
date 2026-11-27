using System.Net;
using System.Net.Sockets;

namespace WinClient.Core.Firewall;

public enum WfpLayer { ConnectV4, ConnectV6, AcceptV4, AcceptV6 }
public enum WfpAction { Permit, Block }

public sealed record WfpFilterSpec(string Name, WfpLayer Layer, WfpAction Action, byte Weight,
    string? AppPath = null, string[]? RemoteAddresses = null, string? LocalAddress = null,
    string? Protocol = null, int? LocalPort = null, int? RemotePort = null, bool Loopback = false);

/// <summary>纯策略计算；同字段连续地址条件为或，不同字段为且。</summary>
public static class WfpPlanner
{
    public const string Prefix = "YuanC-WFP-";
    public const string MissingMarker = "YuanC-WFP";
    public const byte PermitWeight = 10;
    public const byte BlockWeight = 0;
    public const byte ExactPermitWeight = 12;
    public const byte DnsBlockWeight = 11;
    public const int DnsPort = 53;
    public const string TunAddressV6 = "fdfe:dcba:9876::1";
    public static readonly string[] LanV4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"];
    public static readonly string[] LanV6 = ["fe80::/10", "ff00::/8"];
    private static readonly WfpLayer[] Layers = [WfpLayer.ConnectV4, WfpLayer.ConnectV6, WfpLayer.AcceptV4, WfpLayer.AcceptV6];
    private static bool IsV4(WfpLayer layer) => layer is WfpLayer.ConnectV4 or WfpLayer.AcceptV4;

    public static IReadOnlyList<WfpFilterSpec> PlanGlobal(IReadOnlyList<IPAddress> nodeIps,
        string programPath, int hy2Port, int realityPort = 443, AuthEndpoint? auth = null)
    {
        // 保持 KillSwitchPlanner.NodeRules 的校验次序、参数名和报错文字。
        var program = programPath;
        var ips = nodeIps;
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        if (!Path.IsPathFullyQualified(program)) throw new ArgumentException("连接内核路径必须是绝对路径。", nameof(program));
        if (ips.Count == 0 || ips.Any(ip => ip.AddressFamily != AddressFamily.InterNetwork))
            throw new ArgumentException("节点必须提供至少一个 IPv4 地址。", nameof(ips));
        if (hy2Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(hy2Port));
        if (realityPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(realityPort));
        if (auth is not null)
        {
            if (auth.Address is null || auth.Address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("鉴权服务器必须是 IPv4 数字地址。", nameof(auth));
            if (auth.Port is < 1 or > 65535)
                throw new ArgumentException("鉴权服务器端口必须在 1 到 65535 之间。", nameof(auth));
            if (string.IsNullOrWhiteSpace(auth.Program) || !Path.IsPathFullyQualified(auth.Program))
                throw new ArgumentException("后台服务程序必须是绝对路径。", nameof(auth));
        }
        var result = new List<WfpFilterSpec>();
        foreach (var layer in Layers)
            result.Add(new(Prefix + "Loopback-" + layer, layer, WfpAction.Permit, ExactPermitWeight, Loopback: true));
        foreach (var layer in Layers)
            result.Add(new(Prefix + "Tun-" + layer, layer, WfpAction.Permit, ExactPermitWeight,
                LocalAddress: IsV4(layer) ? KillSwitchPlanner.TunAddress : TunAddressV6));
        foreach (var layer in Layers)
            result.Add(new(Prefix + "Lan-" + layer, layer, WfpAction.Permit, PermitWeight,
                RemoteAddresses: (IsV4(layer) ? LanV4 : LanV6).ToArray()));
        foreach (var layer in new[] { WfpLayer.ConnectV4, WfpLayer.AcceptV4 })
            result.Add(new(Prefix + "Dhcp-" + layer, layer, WfpAction.Permit, PermitWeight,
                Protocol: "UDP", LocalPort: 68, RemotePort: 67));
        var addresses = ips.Select(ip => ip.ToString()).Distinct().Order().Select(ip => ip + "/32").ToArray();
        result.Add(new(Prefix + "Node-Tcp", WfpLayer.ConnectV4, WfpAction.Permit, ExactPermitWeight,
            program, addresses, Protocol: "TCP", RemotePort: realityPort));
        result.Add(new(Prefix + "Node-Udp", WfpLayer.ConnectV4, WfpAction.Permit, ExactPermitWeight,
            program, addresses.ToArray(), Protocol: "UDP", RemotePort: hy2Port));
        if (auth is not null)
            result.Add(new(Prefix + "Auth", WfpLayer.ConnectV4, WfpAction.Permit, ExactPermitWeight,
                auth.Program, [auth.Address + "/32"], Protocol: "TCP", RemotePort: auth.Port));
        foreach (var layer in Layers)
            result.Add(new(Prefix + "Block-" + layer, layer, WfpAction.Block, BlockWeight));
        // 域名查询端口阻断排在局域网放行之上、精确放行之下,内核不在时也不把查询交给路由器。
        foreach (var layer in new[] { WfpLayer.ConnectV4, WfpLayer.ConnectV6 })
            result.Add(new(Prefix + "Dns53-" + layer, layer, WfpAction.Block, DnsBlockWeight, RemotePort: DnsPort));
        return result.AsReadOnly();
    }

    public static IReadOnlyList<WfpFilterSpec> PlanApps(IReadOnlyList<string> programs)
    {
        if (programs.Count is < 1 or > 2080 || programs.Any(path => string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)))
            throw new ArgumentException("仅指定程序模式必须提供 1 到 2080 个程序的绝对路径。");
        var result = new List<WfpFilterSpec>();
        for (var i = 0; i < programs.Count; i++)
        {
            foreach (var layer in new[] { WfpLayer.ConnectV4, WfpLayer.ConnectV6 })
            {
                var prefix = Prefix + "App" + (i + 1) + "-";
                result.Add(new(prefix + "Loopback-" + layer, layer, WfpAction.Permit, PermitWeight, programs[i], Loopback: true));
                result.Add(new(prefix + "Tun-" + layer, layer, WfpAction.Permit, PermitWeight, programs[i],
                    LocalAddress: IsV4(layer) ? KillSwitchPlanner.TunAddress : TunAddressV6));
                result.Add(new(prefix + "Block-" + layer, layer, WfpAction.Block, BlockWeight, programs[i]));
            }
        }
        return result.AsReadOnly();
    }
}
