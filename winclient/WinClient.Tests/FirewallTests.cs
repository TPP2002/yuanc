using System.Diagnostics;
using System.Net;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class FirewallTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.5")];
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    [Fact]
    public void ApplyHasOnlyApprovedAllowsAndAuditDoesNotModifyOtherRules()
    {
        var plan = KillSwitchPlanner.Plan(Ips, "YuanC-TUN", ProgramPath, 8443, KillSwitchMode.Apply);
        Assert.Equal(new[] { "Domain", "Private", "Public" }, plan.OfType<SetProfileDefault>().Select(p => p.Profile));
        Assert.All(plan.OfType<SetProfileDefault>(), p => Assert.Equal("Block", p.Action));
        var rules = plan.OfType<AddRule>().ToArray();
        Assert.Equal(5, rules.Length);
        Assert.All(rules, r => { Assert.Equal("Allow", r.Action); Assert.Equal("Outbound", r.Direction); Assert.StartsWith("YuanC-KS-", r.Name); });
        var tcp = rules.Single(r => r.Name == "YuanC-KS-Node-Tcp");
        Assert.Equal(ProgramPath, tcp.Program); Assert.Equal(new[] { "192.0.2.5" }, tcp.RemoteAddress);
        Assert.Equal("TCP", tcp.Protocol); Assert.Equal("443", tcp.RemotePort);
        Assert.Equal("8443", rules.Single(r => r.Name.EndsWith("Node-Udp")).RemotePort);
        Assert.Equal("YuanC-TUN", rules.Single(r => r.Name.EndsWith("Tun")).InterfaceAlias);
        Assert.Equal(new[] { "127.0.0.0/8", "::1" }, rules.Single(r => r.Name.EndsWith("Loopback")).RemoteAddress);
        var dhcp = rules.Single(r => r.Name.EndsWith("Dhcp"));
        Assert.Equal("UDP", dhcp.Protocol); Assert.Equal("68", dhcp.LocalPort); Assert.Equal("67", dhcp.RemotePort);
        Assert.Single(plan.OfType<Audit>());
        Assert.DoesNotContain(rules, r => r.RemotePort == "53");
        var script = KillSwitchPlanner.ToPowerShellScript(plan, "state.json", "audit.json");
        Assert.Contains("Set-NetFirewallProfile -Enabled True -DefaultOutboundAction Block", script);
        Assert.Contains("$_.Name -notlike 'YuanC-KS-*'", script);
        Assert.Contains("Get-NetFirewallApplicationFilter", script);
        Assert.DoesNotContain("Set-NetFirewallRule", script);
        Assert.All(script.Split('\n').Where(line => line.Contains("Remove-NetFirewallRule", StringComparison.Ordinal)),
            line => Assert.Matches("^Get-NetFirewallRule -Name 'YuanC-KS-[^']+' -ErrorAction SilentlyContinue \\| Remove-NetFirewallRule\\r?$", line));
        var disabledRulesRecord = script.IndexOf("$state.disabledRules = @(", StringComparison.Ordinal);
        Assert.True(disabledRulesRecord >= 0);
        var disabledRulesWrite = script.IndexOf("Write-State $state", disabledRulesRecord, StringComparison.Ordinal);
        Assert.True(disabledRulesWrite > disabledRulesRecord);
        Assert.True(script.IndexOf("Disable-NetFirewallRule", StringComparison.Ordinal) > disabledRulesWrite);
        Assert.DoesNotContain("Enable-NetFirewallRule", script);
        var restoreScript = KillSwitchPlanner.ToPowerShellScript([new RestoreProfileDefault()], "state.json", "audit.json");
        Assert.Contains("Enable-NetFirewallRule", restoreScript);
        Assert.True(script.IndexOf("Write-State $state", StringComparison.Ordinal) < script.IndexOf("Set-NetFirewallProfile", StringComparison.Ordinal));
        Assert.True(script.LastIndexOf("$state.applied = $true", StringComparison.Ordinal) > script.IndexOf("New-NetFirewallRule", StringComparison.Ordinal));
    }
    [Fact]
    public void NodeUpdateLeavesProfileTunDhcpAndLoopbackUntouched()
    {
        var update = KillSwitchPlanner.UpdateNode([IPAddress.Parse("192.0.2.6")], ProgramPath, 8443);
        Assert.Equal("YuanC-KS-Node-", Assert.Single(update.OfType<RemoveRulesByPrefix>()).Prefix);
        Assert.Equal(2, update.OfType<AddRule>().Count());
        Assert.All(update.OfType<AddRule>(), r => Assert.Equal(new[] { "192.0.2.6" }, r.RemoteAddress));
        Assert.Empty(update.OfType<RestoreProfileDefault>()); Assert.Empty(update.OfType<SetProfileDefault>());
        var script = KillSwitchPlanner.ToPowerShellScript(update, "state.json", "audit.json");
        Assert.DoesNotContain("Set-NetFirewallProfile", script);
        Assert.DoesNotContain("YuanC-KS-Tun", script);
        Assert.DoesNotContain("YuanC-KS-Loopback", script);
        Assert.DoesNotContain("YuanC-KS-Dhcp", script);
    }
    [Fact]
    public void RemoveUsesSavedDefaultsAndExplicitNoSnapshotFallback()
    {
        var plan = KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove);
        Assert.Equal("YuanC-KS-", Assert.Single(plan.OfType<RemoveRulesByPrefix>()).Prefix);
        Assert.Single(plan.OfType<RestoreProfileDefault>());
        var script = KillSwitchPlanner.ToPowerShellScript(plan, "state.json", "audit.json");
        Assert.Contains("-DefaultOutboundAction $p.DefaultOutboundAction", script);
        Assert.Contains("-Profile Domain,Private,Public -DefaultOutboundAction Allow", script);
        Assert.Throws<ArgumentException>(() => KillSwitchPlanner.ToPowerShellScript([new RemoveRulesByPrefix("Other-")], "state.json", "audit.json"));
    }
    [Fact]
    public async Task RunnerIsInjectableHiddenAndFailuresAreNotSuccess()
    {
        using var directory = new TempDirectory(); var runner = new RecordingRunner();
        var applier = new KillSwitchApplier(directory.Path, runner);
        await applier.ApplyAsync(Ips, ProgramPath, 8443);
        Assert.True(runner.Last.CreateNoWindow); Assert.False(runner.Last.UseShellExecute);
        Assert.Contains("-NonInteractive", runner.Last.ArgumentList);
        Assert.Contains("-Command", runner.Last.ArgumentList);
        runner.ExitCode = 1;
        await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RemoveAsync());
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task RecoveryIncludesInterruptedApply(bool applied)
    {
        using var directory = new TempDirectory(); var runner = new RecordingRunner();
        var applier = new KillSwitchApplier(directory.Path, runner);
        await applier.RecoverAsync(); Assert.Equal(0, runner.Calls);
        File.WriteAllText(applier.StatePath, "{\"applied\":" + applied.ToString().ToLowerInvariant() + "}");
        await applier.RecoverAsync(); Assert.Equal(1, runner.Calls);
        Assert.Contains("-DefaultOutboundAction $p.DefaultOutboundAction", runner.Last.ArgumentList.Last());
    }
    [Fact]
    public void PowerShellArgumentsAreLiteralQuoted()
    {
        var script = KillSwitchPlanner.ToPowerShellScript(
            [new AddRule("YuanC-KS-Test", "Outbound", "Allow", Program: "C:\\O'Brien\\$(test).exe")], "state.json", "audit.json");
        Assert.Contains("'C:\\O''Brien\\$(test).exe'", script);
    }
    private sealed class RecordingRunner : ICommandRunner
    {
        public ProcessStartInfo Last { get; private set; } = new() { CreateNoWindow = true, UseShellExecute = false };
        public int ExitCode { get; set; }
        public int Calls { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        { Last = startInfo; Calls++; return Task.FromResult(new CommandResult(ExitCode, "")); }
    }
}

internal sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "YuanC-tests-" + Guid.NewGuid().ToString("N"));
    public TempDirectory() => Directory.CreateDirectory(Path);
    public void Dispose() => Directory.Delete(Path, recursive: true);
}
