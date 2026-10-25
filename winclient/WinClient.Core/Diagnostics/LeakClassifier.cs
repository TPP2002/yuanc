using System.Net;
using System.Net.Sockets;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

/// <summary>归类所需的上下文。LocalAddresses 只用于判断对端,绝不写进结果。</summary>
public sealed record LeakContext(IReadOnlySet<IPAddress> LocalAddresses, IReadOnlySet<IPAddress> NodeAddresses,
    IPEndPoint? Auth, bool AppsMode, IReadOnlyList<string> Apps);

public sealed record SuspiciousFlow(string Protocol, string Remote, int RemotePort, string? Process, bool? Listed, int Count);

public sealed record LeakVerdict(int Total, int Tunnel, int Allowed, int Unparsed, IReadOnlyList<SuspiciousFlow> Suspicious);

public static class LeakClassifier
{
    private static readonly byte[] TunnelV4 = [172, 19, 0, 0];
    private static readonly byte[] TunnelV6 = [0xFD, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    public static LeakVerdict Classify(IEnumerable<CapturedPacket> packets, LeakContext context, Func<CapturedPacket, string?> owner)
    {
        int total = 0, tunnel = 0, allowed = 0, unparsed = 0;
        var flows = new Dictionary<(string, string, int, string?), int>();
        var order = new List<(string, string, int, string?)>();
        foreach (var packet in packets)
        {
            total++;
            if (packet.Source is null || packet.Destination is null) { unparsed++; continue; }
            if (IsTunnel(packet.Source) || IsTunnel(packet.Destination)) { tunnel++; continue; }
            var remote = FindSuspiciousPeer(packet, context);
            if (remote is null) { allowed++; continue; }
            var (address, port) = remote.Value;
            var key = (packet.Protocol, address.ToString(), port, owner(packet));
            if (flows.TryGetValue(key, out var count)) flows[key] = count + 1;
            else { flows[key] = 1; order.Add(key); }
        }
        var suspicious = order.Select(key => new SuspiciousFlow(key.Item1, key.Item2, key.Item3, key.Item4,
            Listed(key.Item4, context), flows[key])).OrderByDescending(flow => flow.Count).ToArray();
        return new(total, tunnel, allowed, unparsed, suspicious);
    }

    /// <summary>仅指定程序模式下的退出码口径:0 无可疑(或可疑流都在名单外),1 有可疑,由调用方在无法检测时自行用 2。</summary>
    public static int ExitCode(LeakVerdict verdict, bool appsMode) =>
        verdict.Suspicious.Any(flow => !appsMode || flow.Listed != false) ? 1 : 0;

    // 对端 = 两端里不属于本机的那个;都属于或都不属于时两端都当候选,但本机地址永不作为候选。
    private static (IPAddress, int)? FindSuspiciousPeer(CapturedPacket packet, LeakContext context)
    {
        var source = packet.Source!;
        var destination = packet.Destination!;
        var sourceLocal = context.LocalAddresses.Contains(source);
        var destinationLocal = context.LocalAddresses.Contains(destination);
        if (!destinationLocal && IsSuspicious(destination, packet.DestinationPort, packet, context))
            return (destination, packet.DestinationPort);
        if (!sourceLocal && IsSuspicious(source, packet.SourcePort, packet, context))
            return (source, packet.SourcePort);
        return null;
    }

    private static bool IsSuspicious(IPAddress peer, int port, CapturedPacket packet, LeakContext context)
    {
        if (!PublicAddress.IsPublic(peer)) return false;
        if (context.NodeAddresses.Contains(peer)) return false;
        return !(context.Auth is { } auth && packet.Protocol == "TCP" && auth.Address.Equals(peer) && auth.Port == port);
    }

    private static bool? Listed(string? process, LeakContext context)
    {
        if (!context.AppsMode || process is null) return null;
        var path = Normalize(process);
        foreach (var app in context.Apps)
        {
            var listed = Normalize(app);
            if (string.Equals(path, listed, StringComparison.OrdinalIgnoreCase)) return true;
            var slash = listed.LastIndexOf('\\');
            if (slash > 0 && path.StartsWith(listed[..(slash + 1)], StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string Normalize(string path) => path.Replace('/', '\\');

    private static bool IsTunnel(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return bytes[0] == TunnelV4[0] && bytes[1] == TunnelV4[1] && bytes[2] == 0 && bytes[3] <= 3;
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        for (var i = 0; i < 14; i++) if (bytes[i] != TunnelV6[i]) return false;
        return bytes[14] == 0 && bytes[15] <= 3;
    }
}
