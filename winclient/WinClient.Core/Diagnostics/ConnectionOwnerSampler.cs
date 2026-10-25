using System.ComponentModel;
using System.Net;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

/// <summary>
/// 抓包期间按固定间隔(默认 500 毫秒)采样 TCP / UDP 连接表,累积「连接 → 进程路径」。
/// 极短的连接可能没采到,此时归属为 null(归属未知)。
/// </summary>
public sealed class ConnectionOwnerSampler(ITcpTable tcp, IUdpTable udp)
{
    public static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(500);

    private readonly Dictionary<(int, IPAddress, int), string> tcpOwners = [];
    private readonly Dictionary<int, string> udpOwners = [];

    /// <summary>采样一次。读表失败(权限、系统限制)只跳过这一次,不中断检测。</summary>
    public void Sample()
    {
        try
        {
            foreach (var entry in tcp.Snapshot())
            {
                if (entry.ProcessPath is not { Length: > 0 } path || entry.State is 1 or 2 or 12) continue;
                tcpOwners[(entry.LocalPort, entry.Remote, entry.RemotePort)] = path;
            }
        }
        catch (Win32Exception) { }
        try
        {
            foreach (var entry in udp.Snapshot())
                if (entry.ProcessPath is { Length: > 0 } path) udpOwners[entry.LocalPort] = path;
        }
        catch (Win32Exception) { }
    }

    /// <summary>先按包的源端口(本机发出)再按目的端口(发往本机)查。</summary>
    public string? Owner(CapturedPacket packet)
    {
        if (packet.Protocol == "TCP" && packet.Source is not null && packet.Destination is not null)
        {
            if (tcpOwners.TryGetValue((packet.SourcePort, packet.Destination, packet.DestinationPort), out var outbound)) return outbound;
            if (tcpOwners.TryGetValue((packet.DestinationPort, packet.Source, packet.SourcePort), out var inbound)) return inbound;
        }
        else if (packet.Protocol == "UDP")
        {
            if (udpOwners.TryGetValue(packet.SourcePort, out var outbound)) return outbound;
            if (udpOwners.TryGetValue(packet.DestinationPort, out var inbound)) return inbound;
        }
        return null;
    }
}
