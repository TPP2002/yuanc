using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WinClient.Core.Network;

/// <summary>
/// 经 iphlpapi 读取 IPv4 TCP 表并用 SetTcpEntry 重置连接(把状态设为 DELETE_TCB)。
/// 需要管理员权限;重置失败只返回 false,不记录地址与端口。
/// </summary>
public sealed class SystemTcpTable : ITcpTable
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;
    private const int DeleteTcb = 12;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    // MIB_TCPROW_OWNER_PID:六个 DWORD,地址与端口都是网络字节序。
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State; public uint LocalAddr; public uint LocalPort; public uint RemoteAddr; public uint RemotePort; public uint OwningPid;
    }

    // MIB_TCPROW:五个 DWORD。
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State; public uint LocalAddr; public uint LocalPort; public uint RemoteAddr; public uint RemotePort;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetTcpEntry(ref MibTcpRow row);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

    public IReadOnlyList<TcpEntry> Snapshot()
    {
        var buffer = IntPtr.Zero;
        try
        {
            var size = 0;
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
            for (var attempt = 0; attempt < 8 && result == ErrorInsufficientBuffer; attempt++)
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                size += 4096; // 表在两次调用之间可能增长。
                buffer = Marshal.AllocHGlobal(size);
                result = GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
            }
            if (result != 0 || buffer == IntPtr.Zero) throw new Win32Exception((int)result);
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var paths = new Dictionary<int, string?>();
            var entries = new List<TcpEntry>(count);
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buffer + 4 + i * rowSize);
                var pid = (int)row.OwningPid;
                if (!paths.TryGetValue(pid, out var path)) paths[pid] = path = ImagePath(row.OwningPid);
                entries.Add(new((int)row.State, ToAddress(row.LocalAddr), ToPort(row.LocalPort),
                    ToAddress(row.RemoteAddr), ToPort(row.RemotePort), pid, path));
            }
            return entries;
        }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    public bool Reset(TcpEntry entry)
    {
        var row = new MibTcpRow
        {
            State = DeleteTcb, LocalAddr = FromAddress(entry.Local), LocalPort = FromPort(entry.LocalPort),
            RemoteAddr = FromAddress(entry.Remote), RemotePort = FromPort(entry.RemotePort)
        };
        return SetTcpEntry(ref row) == 0;
    }

    // DWORD 在内存中的字节顺序就是 a.b.c.d,小端读出后按字节还原。
    private static IPAddress ToAddress(uint value) => new(BitConverter.GetBytes(value));
    private static uint FromAddress(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes(), 0);
    // 端口在低 16 位里按网络字节序存放。
    private static int ToPort(uint value) => (int)(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));
    private static uint FromPort(int port) => (uint)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));

    private static string? ImagePath(uint pid)
    {
        if (pid == 0) return null;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var name = new StringBuilder(1024);
            var size = name.Capacity;
            return QueryFullProcessImageName(handle, 0, name, ref size) ? name.ToString(0, size) : null;
        }
        finally { CloseHandle(handle); }
    }
}
