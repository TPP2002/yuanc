using System.Net;
using WinClient.Core.Firewall;
using WinClient.Core.Pairing;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchNarrowRuleTests
{
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    private static string Script(IReadOnlyList<FirewallAction> actions) => KillSwitchPlanner.ToPowerShellScript(actions, "state.json", "audit.json");
    private static string Line(string script, string name) =>
        script.Split('\n').Single(l => l.StartsWith("New-NetFirewallRule -Name '" + name + "'", StringComparison.Ordinal));

    private static string ApplyScript() =>
        Script(KillSwitchPlanner.Plan([IPAddress.Parse("192.0.2.5")], "YuanC-TUN", ProgramPath, 8443, KillSwitchMode.Apply));

    [Fact]
    public void DhcpRuleOnlyAllowsDhcpServiceToBroadcastAndLocalSubnet()
    {
        var line = Line(ApplyScript(), "YuanC-KS-Dhcp");
        Assert.Contains("-Program '" + KillSwitchPlanner.DhcpProgram.Replace("'", "''") + "'", line);
        Assert.Contains("-Service 'Dhcp'", line);
        Assert.Contains("-RemoteAddress @('255.255.255.255','LocalSubnet')", line);
        Assert.Contains("-Protocol 'UDP' -LocalPort '68' -RemotePort '67'", line);
    }

    [Fact]
    public void TunRuleMatchesLocalAddressWithoutInterfaceAlias()
    {
        var line = Line(ApplyScript(), "YuanC-KS-Tun");
        Assert.Contains("-LocalAddress @('172.19.0.1')", line);
        Assert.DoesNotContain("-InterfaceAlias", line);
    }

    [Fact]
    public void LocalAddressAndAliasBothEmittedWithLocalAddressBeforeRemoteAddress()
    {
        var rule = new AddRule("YuanC-KS-Test", "Outbound", "Allow", RemoteAddress: ["192.0.2.1"],
            InterfaceAlias: "Alias", LocalAddress: ["10.0.0.1"]);
        var line = Line(Script([rule]), "YuanC-KS-Test");
        Assert.Contains("-LocalAddress @('10.0.0.1')", line);
        Assert.Contains("-InterfaceAlias 'Alias'", line);
        Assert.True(line.IndexOf("-LocalAddress", StringComparison.Ordinal) < line.IndexOf("-RemoteAddress", StringComparison.Ordinal));
    }

    [Fact]
    public void ServiceWithSingleQuoteIsEscaped()
    {
        var line = Line(Script([new AddRule("YuanC-KS-Test", "Outbound", "Allow", Service: "a'b")]), "YuanC-KS-Test");
        Assert.Contains("-Service 'a''b'", line);
    }

    [Fact]
    public void NodeUpdateStillHasNoTunOrDhcp()
    {
        var script = Script(KillSwitchPlanner.UpdateNode([IPAddress.Parse("192.0.2.6")], ProgramPath, 8443));
        Assert.DoesNotContain("YuanC-KS-Tun", script);
        Assert.DoesNotContain("YuanC-KS-Dhcp", script);
    }

    [Fact]
    public void TunAddressMatchesRenderedTunnelInboundAddress()
    {
        var rendered = LocalConfigRenderer.Render(PairingTests.ValidPairing().Node);
        var address = rendered.GetProperty("inbounds")[0].GetProperty("address")[0].GetString();
        Assert.Equal(KillSwitchPlanner.TunAddress + "/30", address);
    }
}
