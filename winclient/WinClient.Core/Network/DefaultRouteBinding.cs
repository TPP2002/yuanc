using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using WinClient.Core.Firewall;

namespace WinClient.Core.Network;

public sealed record DefaultRoute(int InterfaceIndex, string Alias, long Metric);

/// <summary>鉴权直连使用物理默认出口，避免被回环兜底路由接走。</summary>
public static class DefaultRouteBinding
{
    private const ushort AfInet = 2;

    public static int? Pick(IEnumerable<DefaultRoute> routes, int loopbackIndex) => routes
        .Where(route => route.InterfaceIndex != loopbackIndex &&
            !string.Equals(route.Alias, KillSwitchPlanner.TunAlias, StringComparison.OrdinalIgnoreCase))
        .OrderBy(route => route.Metric).ThenBy(route => route.InterfaceIndex)
        .Select(route => (int?)route.InterfaceIndex).FirstOrDefault();

    public static IReadOnlyList<DefaultRoute> ReadSystem()
    {
        if (!OperatingSystem.IsWindows()) return [];
        IntPtr table = IntPtr.Zero;
        try
        {
            if (GetIpForwardTable2(AfInet, out table) != 0 || table == IntPtr.Zero) return [];
            var count = Marshal.ReadInt32(table);
            var offset = Marshal.OffsetOf<ForwardTable>(nameof(ForwardTable.First)).ToInt32();
            var size = Marshal.SizeOf<ForwardRow>();
            var routes = new List<DefaultRoute>();
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<ForwardRow>(IntPtr.Add(table, checked(offset + i * size)));
                if (row.DestinationPrefix.Length != 0 || row.DestinationPrefix.Address.Family != AfInet ||
                    row.DestinationPrefix.Address.Ipv4 != 0) continue;
                var ipInterface = new InterfaceRow { Family = AfInet, InterfaceIndex = row.InterfaceIndex, ZoneIndices = new uint[16] };
                if (GetIpInterfaceEntry(ref ipInterface) != 0 ||
                    ConvertInterfaceIndexToLuid(row.InterfaceIndex, out var luid) != 0) return [];
                var alias = new StringBuilder(257);
                if (ConvertInterfaceLuidToAlias(ref luid, alias, (UIntPtr)257) != 0) return [];
                routes.Add(new(checked((int)row.InterfaceIndex), alias.ToString(), (long)row.Metric + ipInterface.Metric));
            }
            return routes;
        }
        catch (Exception) { return []; }
        finally { if (table != IntPtr.Zero) FreeMibTable(table); }
    }

    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken token)
    {
        var ipv4 = IPAddress.TryParse(context.DnsEndPoint.Host, out var address) && address.AddressFamily == AddressFamily.InterNetwork;
        var socket = ipv4 ? new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            : new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            if (ipv4 && Pick(ReadSystem(), NetworkInterface.LoopbackInterfaceIndex) is { } index)
                socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31 /* IP_UNICAST_IF */, IPAddress.HostToNetworkOrder(index));
            await socket.ConnectAsync(context.DnsEndPoint, token).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch { socket.Dispose(); throw; }
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpInterfaceEntry(ref InterfaceRow row);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint ConvertInterfaceIndexToLuid(uint index, out ulong luid);
    [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint ConvertInterfaceLuidToAlias(ref ulong luid, StringBuilder alias, UIntPtr length);

    // 以下结构与 Windows SDK 的 SOCKADDR_INET、MIB_IPFORWARD_ROW2、MIB_IPINTERFACE_ROW 对齐。
    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private struct SocketAddress
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(4)] public uint Ipv4;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AddressPrefix
    {
        public SocketAddress Address;
        public byte Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ForwardRow
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public AddressPrefix DestinationPrefix;
        public SocketAddress NextHop;
        public byte SitePrefixLength;
        public uint ValidLifetime, PreferredLifetime, Metric, Protocol;
        public byte Loopback, AutoconfigureAddress, Publish, Immortal;
        public uint Age, Origin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ForwardTable
    {
        public uint Count;
        public ForwardRow First;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct InterfaceRow
    {
        public ushort Family;
        public ulong InterfaceLuid;
        public uint InterfaceIndex, MaxReassemblySize;
        public ulong InterfaceIdentifier;
        public uint MinRouterAdvertisementInterval, MaxRouterAdvertisementInterval;
        public byte AdvertisingEnabled, ForwardingEnabled, WeakHostSend, WeakHostReceive, UseAutomaticMetric;
        public byte UseNeighborUnreachabilityDetection, ManagedAddressConfigurationSupported;
        public byte OtherStatefulConfigurationSupported, AdvertiseDefaultRoute;
        public uint RouterDiscoveryBehavior, DadTransmits, BaseReachableTime, RetransmitTime, PathMtuDiscoveryTimeout;
        public uint LinkLocalAddressBehavior, LinkLocalAddressTimeout;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public uint[] ZoneIndices;
        public uint SitePrefixLength, Metric, NlMtu;
        public byte Connected, SupportsWakeUpPatterns, SupportsNeighborDiscovery, SupportsRouterDiscovery;
        public uint ReachableTime;
        public byte TransmitOffload, ReceiveOffload, DisableDefaultRoutes;
    }
}
