using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WinClient.Core.Network;

/// <summary>UDP 表的一行(只关心本地端口与所属进程)。</summary>
public sealed record UdpEntry(IPAddress Local, int LocalPort, int Pid, string? ProcessPath);

public interface IUdpTable
{
    IReadOnlyList<UdpEntry> Snapshot();
}

/// <summary>经 iphlpapi 读取 IPv4 与 IPv6 的 UDP 表(UDP_TABLE_OWNER_PID),只读,不改任何连接。</summary>
public sealed class SystemUdpTable : IUdpTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    // MIB_UDPROW_OWNER_PID:地址、端口、进程号各一个 DWORD。
    private const int RowSizeV4 = 12;
    // MIB_UDP6ROW_OWNER_PID:16 字节地址 + 作用域 + 端口 + 进程号。
    private const int RowSizeV6 = 28;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

    public IReadOnlyList<UdpEntry> Snapshot()
    {
        var paths = new Dictionary<int, string?>();
        var entries = new List<UdpEntry>(Read(AfInet, paths));
        try { entries.AddRange(Read(AfInet6, paths)); }
        catch (Win32Exception) { /* 未启用 IPv6 的系统读不到 IPv6 表,不影响 IPv4。 */ }
        return entries;
    }

    private static List<UdpEntry> Read(int family, Dictionary<int, string?> paths)
    {
        var buffer = IntPtr.Zero;
        try
        {
            var size = 0;
            var result = GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UdpTableOwnerPid, 0);
            for (var attempt = 0; attempt < 8 && result == ErrorInsufficientBuffer; attempt++)
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                size += 4096; // 表在两次调用之间可能增长。
                buffer = Marshal.AllocHGlobal(size);
                result = GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0);
            }
            if (result != 0 || buffer == IntPtr.Zero) throw new Win32Exception((int)result);
            var count = Marshal.ReadInt32(buffer);
            var v6 = family == AfInet6;
            var rowSize = v6 ? RowSizeV6 : RowSizeV4;
            var entries = new List<UdpEntry>(count);
            for (var i = 0; i < count; i++)
            {
                var row = buffer + 4 + i * rowSize;
                IPAddress local;
                uint port, pid;
                if (v6)
                {
                    var raw = new byte[16];
                    Marshal.Copy(row, raw, 0, 16);
                    local = new IPAddress(raw);
                    port = (uint)Marshal.ReadInt32(row, 20);
                    pid = (uint)Marshal.ReadInt32(row, 24);
                }
                else
                {
                    local = new IPAddress(BitConverter.GetBytes((uint)Marshal.ReadInt32(row, 0)));
                    port = (uint)Marshal.ReadInt32(row, 4);
                    pid = (uint)Marshal.ReadInt32(row, 8);
                }
                if (!paths.TryGetValue((int)pid, out var path)) paths[(int)pid] = path = ImagePath(pid);
                entries.Add(new(local, (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF)), (int)pid, path));
            }
            return entries;
        }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

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
