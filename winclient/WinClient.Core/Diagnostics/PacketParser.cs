using System.Net;

namespace WinClient.Core.Diagnostics;

/// <summary>把链路层帧解析成 <see cref="CapturedPacket"/>:以太网(含一层 VLAN)与裸 IPv4 / IPv6。</summary>
internal static class PacketParser
{
    public static CapturedPacket Parse(int linkType, ReadOnlySpan<byte> data)
    {
        var unparsed = new CapturedPacket(linkType, null, null, "OTHER", 0, 0);
        ReadOnlySpan<byte> ip;
        switch (linkType)
        {
            case 1:
                if (data.Length < 14) return unparsed;
                var offset = 14;
                var etherType = (data[12] << 8) | data[13];
                if (etherType == 0x8100)
                {
                    if (data.Length < 18) return unparsed;
                    etherType = (data[16] << 8) | data[17];
                    offset = 18;
                }
                if (etherType is not (0x0800 or 0x86DD)) return unparsed;
                ip = data[offset..];
                break;
            case 101 or 228 or 229:
                ip = data;
                break;
            default:
                return unparsed;
        }
        if (ip.Length < 1) return unparsed;
        return (ip[0] >> 4) switch
        {
            4 => ParseV4(linkType, ip) ?? unparsed,
            6 => ParseV6(linkType, ip) ?? unparsed,
            _ => unparsed
        };
    }

    private static CapturedPacket? ParseV4(int linkType, ReadOnlySpan<byte> ip)
    {
        if (ip.Length < 20) return null;
        var header = (ip[0] & 0x0F) * 4;
        if (header < 20) return null;
        var fragmentOffset = ((ip[6] & 0x1F) << 8) | ip[7];
        var protocol = ip[9];
        var source = new IPAddress(ip.Slice(12, 4));
        var destination = new IPAddress(ip.Slice(16, 4));
        var (name, ports) = Transport(protocol, fragmentOffset == 0 && ip.Length >= header ? ip[header..] : default, false);
        return new(linkType, source, destination, name, ports.Source, ports.Destination);
    }

    private static CapturedPacket? ParseV6(int linkType, ReadOnlySpan<byte> ip)
    {
        if (ip.Length < 40) return null;
        var source = new IPAddress(ip.Slice(8, 16));
        var destination = new IPAddress(ip.Slice(24, 16));
        var next = ip[6];
        var offset = 40;
        var fragment = false;
        // 跳过常见扩展头:逐跳 0、路由 43、分片 44、目的选项 60。
        while (next is 0 or 43 or 44 or 60)
        {
            if (ip.Length < offset + 8) { next = 255; fragment = true; break; }
            var following = ip[offset];
            if (next == 44)
            {
                fragment = (((ip[offset + 2] << 8) | ip[offset + 3]) & 0xFFF8) != 0;
                offset += 8;
            }
            else offset += (ip[offset + 1] + 1) * 8;
            next = following;
        }
        var payload = !fragment && offset <= ip.Length ? ip[offset..] : default;
        var (name, ports) = Transport(next, payload, true);
        return new(linkType, source, destination, name, ports.Source, ports.Destination);
    }

    private static (string Name, (int Source, int Destination) Ports) Transport(byte protocol, ReadOnlySpan<byte> payload, bool v6)
    {
        var name = protocol switch { 6 => "TCP", 17 => "UDP", 1 when !v6 => "ICMP", 58 when v6 => "ICMPv6", _ => "OTHER" };
        if (name is "TCP" or "UDP" && payload.Length >= 4)
            return (name, ((payload[0] << 8) | payload[1], (payload[2] << 8) | payload[3]));
        return (name, (0, 0));
    }
}
