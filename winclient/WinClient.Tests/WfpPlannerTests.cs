using System.Net;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class WfpPlannerTests
{
    private static string ProgramPath => Path.GetFullPath("kernel.exe");
    private static IReadOnlyList<WfpFilterSpec> Plan(AuthEndpoint? auth = null) =>
        WfpPlanner.PlanGlobal([IPAddress.Parse("192.0.2.8")], ProgramPath, 24443, 443, auth);

    [Fact]
    public void GlobalHasExactlyTwentyInContractOrder()
    {
        var names = new[] {
            "Loopback-ConnectV4", "Loopback-ConnectV6", "Loopback-AcceptV4", "Loopback-AcceptV6",
            "Tun-ConnectV4", "Tun-ConnectV6", "Tun-AcceptV4", "Tun-AcceptV6",
            "Lan-ConnectV4", "Lan-ConnectV6", "Lan-AcceptV4", "Lan-AcceptV6",
            "Dhcp-ConnectV4", "Dhcp-AcceptV4", "Node-Tcp", "Node-Udp",
            "Block-ConnectV4", "Block-ConnectV6", "Block-AcceptV4", "Block-AcceptV6" };
        Assert.Equal(names.Select(n => "YuanC-WFP-" + n), Plan().Select(f => f.Name));
    }

    [Fact]
    public void AuthIsNarrowAndBetweenNodesAndBlocks()
    {
        var auth = new AuthEndpoint(IPAddress.Parse("192.0.2.9"), 8443, Path.GetFullPath("service.exe"));
        var plan = Plan(auth);
        Assert.Equal(21, plan.Count);
        Assert.Equal("YuanC-WFP-Node-Udp", plan[15].Name);
        Assert.Equal(new WfpFilterSpec("YuanC-WFP-Auth", WfpLayer.ConnectV4, WfpAction.Permit, 10,
            auth.Program, plan[16].RemoteAddresses, Protocol: "TCP", RemotePort: 8443), plan[16]);
        Assert.Equal(new[] { "192.0.2.9/32" }, plan[16].RemoteAddresses);
        Assert.Equal("YuanC-WFP-Block-ConnectV4", plan[17].Name);
    }

    [Fact]
    public void NodesAreDeduplicatedAndSortedAndPortsAreScoped()
    {
        var plan = WfpPlanner.PlanGlobal([IPAddress.Parse("192.0.2.9"), IPAddress.Parse("192.0.2.1"), IPAddress.Parse("192.0.2.9")], ProgramPath, 24443, 8443);
        foreach (var rule in plan.Where(f => f.Name.Contains("Node-")))
        {
            Assert.Equal(new[] { "192.0.2.1/32", "192.0.2.9/32" }, rule.RemoteAddresses);
            Assert.Equal(ProgramPath, rule.AppPath);
            Assert.Equal(WfpLayer.ConnectV4, rule.Layer);
            Assert.Equal(rule.Protocol == "TCP" ? 8443 : 24443, rule.RemotePort);
        }
    }

    [Fact]
    public void BlocksAreUnconditionalAndPermitsHaveHigherWeight()
    {
        var plan = Plan();
        Assert.Equal(4, plan.Count(f => f.Action == WfpAction.Block));
        foreach (var rule in plan)
        {
            if (rule.Action == WfpAction.Block)
                Assert.Equal(new WfpFilterSpec(rule.Name, rule.Layer, WfpAction.Block, 0), rule);
            else Assert.Equal((byte)10, rule.Weight);
        }
        Assert.All(plan.Take(4), f => Assert.True(f.Loopback));
        Assert.Equal(new[] { "172.19.0.1", "fdfe:dcba:9876::1", "172.19.0.1", "fdfe:dcba:9876::1" }, plan.Skip(4).Take(4).Select(f => f.LocalAddress));
        Assert.All(plan.Skip(12).Take(2), f => { Assert.Equal("UDP", f.Protocol); Assert.Equal(68, f.LocalPort); Assert.Equal(67, f.RemotePort); });
    }

    [Fact]
    public void InvalidInputsMatchExistingValidation()
    {
        Assert.ThrowsAny<ArgumentException>(() => WfpPlanner.PlanGlobal([], ProgramPath, 443));
        Assert.ThrowsAny<ArgumentException>(() => WfpPlanner.PlanGlobal([IPAddress.IPv6Loopback], ProgramPath, 443));
        Assert.ThrowsAny<ArgumentException>(() => WfpPlanner.PlanGlobal([IPAddress.Loopback], "relative.exe", 443));
        Assert.ThrowsAny<ArgumentException>(() => WfpPlanner.PlanGlobal([IPAddress.Loopback], ProgramPath, 0));
        Assert.ThrowsAny<ArgumentException>(() => WfpPlanner.PlanGlobal([IPAddress.Loopback], ProgramPath, 443, 65536));
        foreach (var auth in new[] { new AuthEndpoint(IPAddress.IPv6Loopback, 443, ProgramPath), new AuthEndpoint(IPAddress.Loopback, 0, ProgramPath), new AuthEndpoint(IPAddress.Loopback, 443, "relative.exe") })
            Assert.ThrowsAny<ArgumentException>(() => Plan(auth));
    }

    [Fact]
    public void AppsHaveSixRulesEachAndNoGlobalBlock()
    {
        var paths = new[] { ProgramPath, Path.GetFullPath("browser.exe") };
        var plan = WfpPlanner.PlanApps(paths);
        Assert.Equal(12, plan.Count);
        for (var i = 0; i < 2; i++)
        {
            var rules = plan.Skip(i * 6).Take(6).ToArray();
            Assert.All(rules, f => Assert.Equal(paths[i], f.AppPath));
            Assert.Equal(new[] { WfpLayer.ConnectV4, WfpLayer.ConnectV4, WfpLayer.ConnectV4, WfpLayer.ConnectV6, WfpLayer.ConnectV6, WfpLayer.ConnectV6 }, rules.Select(f => f.Layer));
            Assert.All(rules.Where(f => f.Action == WfpAction.Block), f => Assert.Equal(new WfpFilterSpec(f.Name, f.Layer, WfpAction.Block, 0, paths[i]), f));
        }
        Assert.Throws<ArgumentException>(() => WfpPlanner.PlanApps(Enumerable.Repeat(ProgramPath, 2081).ToArray()));
        Assert.Throws<ArgumentException>(() => WfpPlanner.PlanApps([]));
        Assert.Throws<ArgumentException>(() => WfpPlanner.PlanApps(["relative.exe"]));
    }

    [Fact]
    public void AppsAcceptsLargeFilterProgramList()
    {
        var programs = Enumerable.Range(1, 100).Select(i => Path.GetFullPath($"app{i}.exe")).ToArray();
        Assert.Equal(600, WfpPlanner.PlanApps(programs).Count);
        Assert.Equal(2080 * 6, WfpPlanner.PlanApps(Enumerable.Repeat(ProgramPath, 2080).ToArray()).Count);
        var empty = Assert.Throws<ArgumentException>(() => WfpPlanner.PlanApps([]));
        Assert.Equal("仅指定程序模式必须提供 1 到 2080 个程序的绝对路径。", empty.Message);
        Assert.Throws<ArgumentException>(() => WfpPlanner.PlanApps(Enumerable.Repeat(ProgramPath, 2081).ToArray()));
    }

    [Fact]
    public void LanIsExactlyPrivateLinkLocalMulticastAndBroadcast()
    {
        Assert.Equal(new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32" }, WfpPlanner.LanV4);
        Assert.Equal(new[] { "fe80::/10", "ff00::/8" }, WfpPlanner.LanV6);
        Assert.DoesNotContain("0.0.0.0/0", WfpPlanner.LanV4);
        Assert.DoesNotContain("::/0", WfpPlanner.LanV6);
    }
}
