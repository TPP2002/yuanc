using System.ComponentModel;
using System.Net;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

public sealed class StaleConnectionTests
{
    private const string Kernel = @"C:\Program Files\YuanC\sing-box.exe";
    private const string Service = @"C:\Program Files\YuanC\WinClient.App.exe";
    private const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
    private const string Edge = @"C:\Program Files\Microsoft\Edge\Application\msedge.exe";
    private static readonly IPAddress Node = IPAddress.Parse("203.0.113.50");
    private static readonly AuthEndpoint Auth = new(IPAddress.Parse("203.0.113.60"), 8443, Service);

    private static TcpEntry Entry(string remote = "8.8.8.8", string? path = Chrome, int state = 5, string local = "192.168.1.5",
        int remotePort = 443) => new(state, IPAddress.Parse(local), 50000, IPAddress.Parse(remote), remotePort, 100, path);

    private static ReapPolicy Policy(bool apps = false, params string[] list) =>
        new(apps, list, Kernel, [Node], Auth);

    [Fact]
    public void SelectSkipsKernelToNodeAndServiceToAuth()
    {
        // 节点与鉴权地址必须是公网地址才会进入判定,所以这里用真实公网地址。
        var publicNode = new ReapPolicy(false, [], Kernel, [IPAddress.Parse("8.8.8.8")], new(IPAddress.Parse("9.9.9.9"), 8443, Service));
        var all = new[]
        {
            Entry("8.8.8.8", Kernel), Entry("8.8.4.4", Kernel), Entry("8.8.8.8", Chrome),
            Entry("9.9.9.9", Service, remotePort: 8443), Entry("9.9.9.9", Service, remotePort: 9999), Entry("9.9.9.9", Chrome, remotePort: 8443)
        };
        var result = StaleConnectionPlanner.Select(all, publicNode);
        Assert.Equal(new[] { all[1], all[2], all[4], all[5] }, result);
        var noAuth = publicNode with { Auth = null };
        Assert.Contains(all[3], StaleConnectionPlanner.Select(all, noAuth));
    }

    [Fact]
    public void SelectSkipsLanTunnelLoopbackAndClosedStates()
    {
        var kept = Entry("8.8.8.8");
        var entries = new[]
        {
            kept,
            Entry("192.168.1.9"), Entry("10.0.0.1"), Entry("100.64.0.9"), Entry("127.0.0.1"),
            Entry(local: "0.0.0.0"), Entry(local: "127.0.0.1"), Entry(local: "172.19.0.1"), Entry(local: "172.19.0.2"),
            Entry(state: 1), Entry(state: 2), Entry(state: 11), Entry(state: 12)
        };
        Assert.Equal(new[] { kept }, StaleConnectionPlanner.Select(entries, Policy()));
        Assert.Single(StaleConnectionPlanner.Select([Entry(state: 4), Entry(state: 8)], Policy()), x => x.State == 4);
        Assert.Equal(2, StaleConnectionPlanner.Select([Entry(state: 4), Entry(state: 8)], Policy()).Count);
    }

    [Fact]
    public void AppsModeSelectsOnlyListedPrograms()
    {
        var listed = Entry(path: Chrome.ToUpperInvariant());
        var other = Entry(path: Edge);
        var unknown = Entry(path: null);
        var entries = new[] { listed, other, unknown };
        Assert.Equal(new[] { listed }, StaleConnectionPlanner.Select(entries, Policy(true, Chrome)));
        Assert.Equal(new[] { listed, other, unknown }, StaleConnectionPlanner.Select(entries, Policy(false, Chrome)));
        Assert.Equal(new[] { listed, other }, StaleConnectionPlanner.Select(entries, Policy(true, Chrome, Edge)));
    }

    private sealed class FakeTable(List<TcpEntry> entries) : ITcpTable
    {
        public HashSet<TcpEntry> Fail { get; } = [];
        public HashSet<TcpEntry> Throw { get; } = [];
        public List<TcpEntry> Resets { get; } = [];
        public IReadOnlyList<TcpEntry> Snapshot() => entries.ToArray();
        public bool Reset(TcpEntry entry)
        {
            Resets.Add(entry);
            if (Throw.Contains(entry)) throw new Win32Exception(5);
            if (Fail.Contains(entry)) return false;
            entries.Remove(entry);
            return true;
        }
    }

    [Fact]
    public void ReapReportsResetFailedRemaining()
    {
        var good = Entry("8.8.8.8");
        var refused = Entry("8.8.4.4");
        var thrown = Entry("1.1.1.1");
        var skipped = Entry("192.168.1.9");
        var table = new FakeTable([good, refused, thrown, skipped]);
        table.Fail.Add(refused); table.Throw.Add(thrown);
        var report = new ConnectionReaper(table).Reap(Policy());
        Assert.Equal(new ReapReport(1, 2, 2), report);
        Assert.Equal(new[] { good, refused, thrown }, table.Resets);
        var clean = new ConnectionReaper(new FakeTable([Entry("192.168.1.9")])).Reap(Policy());
        Assert.Equal(new ReapReport(0, 0, 0), clean);
    }
}
