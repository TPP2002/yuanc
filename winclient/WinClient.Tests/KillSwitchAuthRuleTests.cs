using System.Diagnostics;
using System.Net;
using System.Text.Json;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchAuthRuleTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.5")];
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    private static AuthEndpoint Endpoint => new(IPAddress.Parse("192.0.2.1"), 8443, Path.GetFullPath("service.exe"));
    private static IReadOnlyList<FirewallAction> Plan(AuthEndpoint? auth = null) =>
        KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 24443, KillSwitchMode.Apply, auth: auth);

    [Fact]
    public void AuthIsTheOnlyInsertedActionBetweenNodeAndTunRules()
    {
        var baseline = Plan();
        var plan = Plan(Endpoint);
        Assert.Equal(baseline.Count + 1, plan.Count);
        var rule = Assert.IsType<AddRule>(plan[6]);
        Assert.Equal("YuanC-KS-Node-Tcp", Assert.IsType<AddRule>(plan[4]).Name);
        Assert.Equal("YuanC-KS-Node-Udp", Assert.IsType<AddRule>(plan[5]).Name);
        Assert.Equal("YuanC-KS-Tun", Assert.IsType<AddRule>(plan[7]).Name);
        Assert.Equal("YuanC-KS-Auth", rule.Name);
        Assert.Equal("Outbound", rule.Direction);
        Assert.Equal("Allow", rule.Action);
        Assert.Equal(Endpoint.Program, rule.Program);
        Assert.Equal(new[] { "192.0.2.1" }, rule.RemoteAddress);
        Assert.Equal("TCP", rule.Protocol);
        Assert.Equal("8443", rule.RemotePort);
        Assert.Null(rule.LocalPort);
        Assert.Null(rule.InterfaceAlias);
        var withoutAuth = plan.Where((_, index) => index != 6).ToArray();
        for (var index = 0; index < baseline.Count; index++)
        {
            Assert.Equal(baseline[index].GetType(), withoutAuth[index].GetType());
            Assert.Equal(JsonSerializer.Serialize(baseline[index], baseline[index].GetType()),
                JsonSerializer.Serialize(withoutAuth[index], withoutAuth[index].GetType()));
        }
    }

    [Fact]
    public void ScriptScopesAuthRuleToServiceIpv4AndTcpPort()
    {
        var script = KillSwitchPlanner.ToPowerShellScript(Plan(Endpoint), "state.json", "audit.json");
        var line = Assert.Single(script.Split('\n').Where(line => line.StartsWith("New-NetFirewallRule -Name 'YuanC-KS-Auth'", StringComparison.Ordinal)));
        Assert.Contains("-Program '" + Endpoint.Program.Replace("'", "''") + "'", line);
        Assert.Contains("-RemoteAddress @('192.0.2.1')", line);
        Assert.Contains("-Protocol 'TCP'", line);
        Assert.Contains("-RemotePort '8443'", line);
    }

    [Theory]
    [InlineData("::1", 8443, false)]
    [InlineData("192.0.2.1", 0, false)]
    [InlineData("192.0.2.1", 65536, false)]
    [InlineData("192.0.2.1", 8443, true)]
    public void InvalidEndpointIsRejectedInChinese(string address, int port, bool relative)
    {
        var error = Assert.Throws<ArgumentException>(() => Plan(new(IPAddress.Parse(address), port, relative ? "service.exe" : Endpoint.Program)));
        Assert.Matches("[\u4e00-\u9fff]", error.Message);
    }

    [Fact]
    public async Task ApplierPassesAuthEndpointAndReportsPendingStateFromFile()
    {
        using var directory = new TempDirectory();
        var runner = new CapturingRunner();
        var applier = new KillSwitchApplier(directory.Path, runner);
        Assert.False(applier.HasPendingState);
        File.WriteAllText(applier.StatePath, "{}");
        Assert.True(applier.HasPendingState);
        await applier.ApplyAsync(Ips, ProgramPath, 24443, 443, Endpoint);
        Assert.Equal(KillSwitchPlanner.ToPowerShellScript(Plan(Endpoint), applier.StatePath, applier.AuditPath), runner.Script);
    }

    private sealed class CapturingRunner : ICommandRunner
    {
        public string? Script { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        { Script = startInfo.ArgumentList.Last(); return Task.FromResult(new CommandResult(0, "")); }
    }
}
