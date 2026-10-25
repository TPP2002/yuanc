using System.Net;
using System.Net.Sockets;

namespace WinClient.Core.Network;

/// <summary>判断一个地址是否属于公网:保留、私有、共享、测试、组播等网段一律不算。</summary>
public static class PublicAddress
{
    // IPv4 非公网网段(网络地址与前缀长度):
    // 0.0.0.0/8、10.0.0.0/8、100.64.0.0/10、127.0.0.0/8、169.254.0.0/16、172.16.0.0/12、192.0.0.0/24、
    // 192.0.2.0/24、192.168.0.0/16、198.18.0.0/15、198.51.100.0/24、203.0.113.0/24、224.0.0.0/4、240.0.0.0/4。
    // IPv6 只认 2000::/3,并排除文档网段 2001:db8::/32。
    private static readonly (uint Network, int Prefix)[] ReservedV4 =
    [
        (V4(0, 0, 0, 0), 8), (V4(10, 0, 0, 0), 8), (V4(100, 64, 0, 0), 10), (V4(127, 0, 0, 0), 8),
        (V4(169, 254, 0, 0), 16), (V4(172, 16, 0, 0), 12), (V4(192, 0, 0, 0), 24), (V4(192, 0, 2, 0), 24),
        (V4(192, 168, 0, 0), 16), (V4(198, 18, 0, 0), 15), (V4(198, 51, 100, 0), 24), (V4(203, 0, 113, 0), 24),
        (V4(224, 0, 0, 0), 4), (V4(240, 0, 0, 0), 4)
    ];

    private static uint V4(byte a, byte b, byte c, byte d) => ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;

    public static bool IsPublic(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv4MappedToIPv6) return IsPublic(address.MapToIPv4());
            var bytes = address.GetAddressBytes();
            // 只有全球单播 2000::/3 才算公网,并排除文档网段 2001:db8::/32。
            if ((bytes[0] & 0xE0) != 0x20) return false;
            return !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8);
        }
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var raw = address.GetAddressBytes();
        var value = V4(raw[0], raw[1], raw[2], raw[3]);
        foreach (var (network, prefix) in ReservedV4)
        {
            var mask = uint.MaxValue << (32 - prefix);
            if ((value & mask) == (network & mask)) return false;
        }
        return true;
    }
}
