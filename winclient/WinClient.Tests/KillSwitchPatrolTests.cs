using System.Diagnostics;
using System.Net;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchPatrolTests
{
    [Theory]
    [InlineData(true, 7)]
    [InlineData(false, 6)]
    public void ExpectedNamesHaveExactOrderAndAuthOnlyForAuthMode(bool withAuth, int count)
    {
        var names = KillSwitchPlanner.ExpectedRuleNames(withAuth);
        Assert.Equal(count, names.Length);
        Assert.Equal(withAuth, names.Contains("YuanC-KS-Auth"));
        var expected = new List<string> { "YuanC-KS-Node-Tcp", "YuanC-KS-Node-Udp" };
        if (withAuth) expected.Add("YuanC-KS-Auth");
        expected.AddRange(["YuanC-KS-Tun", "YuanC-KS-Loopback", "YuanC-KS-Dhcp", "YuanC-KS-Lan"]);
        Assert.Equal(expected, names);
        Assert.Equal("YuanC-KS-Lan", names[^1]);
    }

    [Fact]
    public void PatrolScriptPersistsBeforeDisablingAndOnlyTightensProtection()
    {
        var script = KillSwitchPlanner.ToPowerShellScript([new Patrol(KillSwitchPlanner.ExpectedRuleNames(true))], "state.json", "audit.json");
        foreach (var text in new[] { "-PolicyStore ActiveStore", "Set-NetFirewallProfile", "Disable-NetFirewallRule", "Get-Service MpsSvc", "exit 3", "ConvertTo-Json", "-PolicyStore PersistentStore" })
            Assert.Contains(text, script);
        Assert.True(script.IndexOf("Write-State", StringComparison.Ordinal) < script.IndexOf("Disable-NetFirewallRule", StringComparison.Ordinal));
        // 检查实际写入调用的位置，不能只靠脚本开头的函数声明通过。
        Assert.True(script.IndexOf("Write-State $state", StringComparison.Ordinal) < script.IndexOf("Disable-NetFirewallRule", StringComparison.Ordinal));
        Assert.True(script.IndexOf("Test-Path -LiteralPath $statePath", StringComparison.Ordinal) < script.IndexOf("-PolicyStore PersistentStore", StringComparison.Ordinal));
        Assert.True(script.IndexOf("$missing =", StringComparison.Ordinal) < script.IndexOf("Get-Service MpsSvc", StringComparison.Ordinal));
        Assert.True(script.IndexOf("Get-Service MpsSvc", StringComparison.Ordinal) < script.LastIndexOf("-PolicyStore ActiveStore", StringComparison.Ordinal));
        Assert.DoesNotContain("$state.disabledRules -notcontains", script);
        Assert.Contains("$state.disableFailed", script);
        Assert.Contains("$state.verifyFailed", script);
        foreach (var text in new[] { "New-NetFirewallRule", "Remove-NetFirewallRule", "Enable-NetFirewallRule", "DefaultInboundAction", "CreateDirectory" })
            Assert.DoesNotContain(text, script);
    }

    [Fact]
    public void PatrolChecksEffectiveRuleIntegrityWithoutChangingRules()
    {
        var script = KillSwitchPlanner.ToPowerShellScript([new Patrol(KillSwitchPlanner.ExpectedRuleNames(true))], "state.json", "audit.json");
        foreach (var text in new[] { "Get-NetFirewallRule -PolicyStore ActiveStore -Name", "$rules.Count -ne 1",
            "[string]$r.Enabled -ne 'True'", "-ne 'Allow'", "-ne 'Outbound'", "Get-NetFirewallAddressFilter",
            "Get-NetFirewallApplicationFilter", "Get-NetFirewallPortFilter", "Get-NetFirewallServiceFilter", "$state.rules" })
            Assert.Contains(text, script);
        Assert.DoesNotContain("Set-NetFirewallRule", script);
    }

    [Fact]
    public void PatrolDisablesReenabledNamesAndPersistsUnionFirst()
    {
        var script = KillSwitchPlanner.ToPowerShellScript([new Patrol(KillSwitchPlanner.ExpectedRuleNames(false))], "state.json", "audit.json");
        var foreignLine = Assert.Single(script.Split('\n').Where(line => line.Contains("$foreignRules =", StringComparison.Ordinal)));
        Assert.Contains("-PolicyStore PersistentStore -Enabled True -Direction Outbound -Action Allow", foreignLine);
        Assert.Contains("$_.Name -notlike 'YuanC-KS-*'", foreignLine);
        Assert.DoesNotContain("disabledRules -notcontains", foreignLine);
        Assert.Contains("@($state.disabledRules) + @($foreignRules.Name)", script);
        var record = script.IndexOf("$state.disabledRules = @(", StringComparison.Ordinal);
        var write = script.IndexOf("Write-State $state", record, StringComparison.Ordinal);
        Assert.True(record >= 0 && write > record);
        Assert.True(script.IndexOf("Disable-NetFirewallRule", StringComparison.Ordinal) > write);
        Assert.Contains("else { $newlyDisabled += [string]$rule.Name }", script);
    }

    [Fact]
    public void ApplyRecordsEveryExpectedRuleIncludingNullFields()
    {
        var plan = KillSwitchPlanner.Plan([IPAddress.Parse("192.0.2.5")], KillSwitchPlanner.TunAlias,
            Path.GetFullPath("sing-box.exe"), 8443, KillSwitchMode.Apply);
        var script = KillSwitchPlanner.ToPowerShellScript(plan, "state.json", "audit.json");
        Assert.Contains("Add-Member -NotePropertyName rules", script);
        Assert.Contains("$state.rules", script);
        var records = script.Split('\n').Where(line => line.Contains("Name = 'YuanC-KS-", StringComparison.Ordinal)).ToArray();
        Assert.Equal(6, records.Length);
        foreach (var rule in plan.OfType<AddRule>())
        {
            var line = Assert.Single(records.Where(line => line.Contains("Name = '" + rule.Name + "'", StringComparison.Ordinal)));
            foreach (var field in new[] { "Program", "Service", "LocalAddress", "RemoteAddress", "Protocol", "LocalPort", "RemotePort" })
                Assert.Contains(field + " = ", line);
            Assert.True(script.IndexOf("New-NetFirewallRule -Name '" + rule.Name + "'", StringComparison.Ordinal)
                < script.IndexOf(line, StringComparison.Ordinal));
        }
        var lan = Assert.Single(records.Where(line => line.Contains("Name = 'YuanC-KS-Lan'", StringComparison.Ordinal)));
        foreach (var field in new[] { "Program", "Service", "LocalAddress", "Protocol", "LocalPort", "RemotePort" })
            Assert.Contains(field + " = $null", lan);
        Assert.Contains("RemoteAddress = @('LocalSubnet')", lan);
    }

    [Fact]
    public void UpdateNodeLoadsAndWritesOnlyExistingState()
    {
        var plan = KillSwitchPlanner.UpdateNode([IPAddress.Parse("192.0.2.6")], Path.GetFullPath("sing-box.exe"), 8443);
        var script = KillSwitchPlanner.ToPowerShellScript(plan, "state.json", "audit.json");
        Assert.Contains("if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { $state = $null }", script);
        Assert.Contains("$state.rules", script);
        Assert.Contains("if ($null -ne $state) { Write-State $state }", script);
        Assert.True(script.IndexOf("Test-Path -LiteralPath $statePath", StringComparison.Ordinal) < script.IndexOf("Remove-NetFirewallRule", StringComparison.Ordinal));
        Assert.True(script.LastIndexOf("Write-State $state", StringComparison.Ordinal) > script.LastIndexOf("New-NetFirewallRule", StringComparison.Ordinal));
        foreach (var text in new[] { "Set-NetFirewallProfile", "Disable-NetFirewallRule", "Enable-NetFirewallRule", "CreateDirectory", "$state.applied =" })
            Assert.DoesNotContain(text, script);
    }

    [Fact]
    public void StandaloneAddRuleGeneratesWithNullableExpectedFields()
    {
        var script = KillSwitchPlanner.ToPowerShellScript([new AddRule("YuanC-KS-Test", "Outbound", "Allow", Service: "a'b")], "state.json", "audit.json");
        Assert.Contains("New-NetFirewallRule -Name 'YuanC-KS-Test'", script);
        Assert.Contains("if ($null -ne $state)", script);
        Assert.Contains("Name = 'YuanC-KS-Test'; Program = $null; Service = 'a''b'", script);
        Assert.Contains("LocalAddress = $null; RemoteAddress = $null; Protocol = $null; LocalPort = $null; RemotePort = $null", script);
    }

    [Fact]
    public async Task PatrolParsesOnlyLastNonemptyLineAndUsesHiddenRunner()
    {
        var runner = new Runner(new(0, "非结果输出\r\n{\"reenforced\":[\"Public\"],\"newly_disabled\":[\"foreign\"],\"missing_rules\":[\"YuanC-KS-Tun\"]}\r\n\r\n"));
        var applier = new KillSwitchApplier("run", runner);
        var report = await applier.PatrolAsync(KillSwitchPlanner.ExpectedRuleNames(false));
        Assert.Equal(new[] { "Public" }, report.Reenforced);
        Assert.Equal(new[] { "foreign" }, report.NewlyDisabled);
        Assert.Equal(new[] { "YuanC-KS-Tun" }, report.MissingRules);
        Assert.False(report.Clean);
        Assert.True(PatrolReport.Empty.Clean);
        Assert.True(runner.Start!.CreateNoWindow);
        Assert.True(runner.Token.CanBeCanceled);
    }

    [Theory]
    [InlineData(3, "")]
    [InlineData(1, "")]
    [InlineData(0, "不是结果")]
    [InlineData(0, "{}")]
    [InlineData(0, "{\"reenforced\":null,\"newly_disabled\":[],\"missing_rules\":[]}")]
    public async Task PatrolRejectsFailureExitCodesAndMalformedOutput(int code, string output)
    {
        var applier = new KillSwitchApplier("run", new Runner(new(code, output)));
        if (code == 3)
            await Assert.ThrowsAsync<FirewallIneffectiveException>(() => applier.PatrolAsync([]));
        else
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => applier.PatrolAsync([]));
            Assert.Equal("断网保护巡检失败,请联系管理员。", error.Message);
        }
    }

    private sealed class Runner(CommandResult result) : ICommandRunner
    {
        public ProcessStartInfo? Start { get; private set; }
        public CancellationToken Token { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        { Start = startInfo; Token = cancellationToken; return Task.FromResult(result); }
    }
}
