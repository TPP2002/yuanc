using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using WinClient.Core.Firewall;

namespace WinClient.Core.Network;

/// <summary>TCP 表的一行。State 用 MIB_TCP_STATE 数值:1 CLOSED、2 LISTEN、11 TIME_WAIT、12 DELETE_TCB。</summary>
public sealed record TcpEntry(int State, IPAddress Local, int LocalPort, IPAddress Remote, int RemotePort, int Pid, string? ProcessPath);

public interface ITcpTable
{
    IReadOnlyList<TcpEntry> Snapshot();
    bool Reset(TcpEntry entry);
}

public sealed record ReapPolicy(bool AppsMode, IReadOnlyList<string> Apps, string KernelPath, IReadOnlyList<IPAddress> NodeIps, AuthEndpoint? Auth);

public sealed record ReapReport(int Reset, int Failed, int Remaining);

public interface IConnectionReaper
{
    ReapReport Reap(ReapPolicy policy);
}

/// <summary>选出连接前就已建立、可能仍从物理网卡发出的 IPv4 TCP 连接。</summary>
public static class StaleConnectionPlanner
{
    private static readonly int[] IgnoredStates = [1, 2, 11, 12];

    public static IReadOnlyList<TcpEntry> Select(IEnumerable<TcpEntry> entries, ReapPolicy policy) =>
        entries.Where(entry => Matches(entry, policy)).ToArray();

    private static bool Matches(TcpEntry entry, ReapPolicy policy)
    {
        if (IgnoredStates.Contains(entry.State)) return false;
        if (entry.Local.AddressFamily != AddressFamily.InterNetwork || entry.Remote.AddressFamily != AddressFamily.InterNetwork) return false;
        if (IsLocalExempt(entry.Local)) return false;
        if (!PublicAddress.IsPublic(entry.Remote)) return false;
        var path = entry.ProcessPath;
        if (path is not null && SamePath(path, policy.KernelPath) && policy.NodeIps.Contains(entry.Remote)) return false;
        if (policy.Auth is { } auth && path is not null && SamePath(path, auth.Program)
            && entry.Remote.Equals(auth.Address) && entry.RemotePort == auth.Port) return false;
        if (policy.AppsMode) return !string.IsNullOrEmpty(path) && policy.Apps.Any(app => SamePath(path, app));
        return true;
    }

    // 本机源地址 0.0.0.0、回环 127.0.0.0/8 与隧道网段 172.19.0.0/30 上的连接不在隧道外。
    private static bool IsLocalExempt(IPAddress local)
    {
        var b = local.GetAddressBytes();
        if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) return true;
        if (b[0] == 127) return true;
        return b[0] == 172 && b[1] == 19 && b[2] == 0 && b[3] <= 3;
    }

    private static bool SamePath(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

/// <summary>快照→选择→逐条重置→复查。不记录任何地址与端口。</summary>
public sealed class ConnectionReaper(ITcpTable table) : IConnectionReaper
{
    public ReapReport Reap(ReapPolicy policy)
    {
        var selected = StaleConnectionPlanner.Select(table.Snapshot(), policy);
        int reset = 0, failed = 0;
        foreach (var entry in selected)
        {
            bool ok;
            try { ok = table.Reset(entry); }
            catch (Win32Exception) { ok = false; }
            if (ok) reset++; else failed++;
        }
        var remaining = StaleConnectionPlanner.Select(table.Snapshot(), policy).Count;
        return new(reset, failed, remaining);
    }
}
