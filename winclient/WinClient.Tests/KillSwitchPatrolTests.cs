using System.Diagnostics;
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
        Assert.Contains("$state.disabledRules -notcontains", script);
        Assert.Contains("$state.disableFailed", script);
        Assert.Contains("$state.verifyFailed", script);
        foreach (var text in new[] { "New-NetFirewallRule", "Remove-NetFirewallRule", "Enable-NetFirewallRule", "DefaultInboundAction", "CreateDirectory" })
            Assert.DoesNotContain(text, script);
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
