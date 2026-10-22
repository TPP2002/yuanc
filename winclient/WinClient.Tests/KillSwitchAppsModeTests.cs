using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchAppsModeTests
{
    private sealed class Runner(int exitCode, string output = "") : ICommandRunner
    {
        public string Script = "";
        public Task<CommandResult> RunAsync(System.Diagnostics.ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            Assert.True(startInfo.CreateNoWindow); Assert.False(startInfo.UseShellExecute);
            Script = startInfo.ArgumentList.Last();
            return Task.FromResult(new CommandResult(exitCode, output));
        }
    }

    [Fact]
    public async Task ApplierMapsIneffectiveRulesAndUsesScopedPatrol()
    {
        using var temp = new TempDirectory();
        var failed = new Runner(3);
        var error = await Assert.ThrowsAsync<FirewallIneffectiveException>(() => new KillSwitchApplier(temp.Path, failed).ApplyAppsAsync([RoutingTests.Chrome]));
        Assert.Equal("系统防火墙未运行、未开启或指定程序的阻断规则未生效,已拒绝连接。请在 Windows 安全中心开启防火墙或联系管理员。", error.Message);
        Assert.Contains("-Action Block", failed.Script);
        var runner = new Runner(0, "{\"reenforced\":[],\"newly_disabled\":[],\"missing_rules\":[\"YuanC-KS-App-1\"]}");
        var report = await new KillSwitchApplier(temp.Path, runner).PatrolAsync(KillSwitchPlanner.AppRuleNames(1), false);
        Assert.Equal("YuanC-KS-App-1", Assert.Single(report.MissingRules));
        Assert.DoesNotContain("-DefaultOutboundAction", runner.Script);
    }
    private static string Script(IReadOnlyList<FirewallAction> actions) => KillSwitchPlanner.ToPowerShellScript(actions, "state.json", "audit.json");
    [Fact]
    public void PlanHasOnlyScopedBlocksAndEnabledProfiles()
    {
        string[] programs = [RoutingTests.Chrome, RoutingTests.Service];
        var plan = KillSwitchPlanner.PlanApps(programs);
        Assert.Equal(new[] { "RecordState", "EnableProfiles", "AddBlockRule", "AddBlockRule", "VerifyRules", "Audit" }, plan.Select(x => x.GetType().Name));
        Assert.Equal("apps", Assert.IsType<RecordState>(plan[0]).Mode);
        Assert.Equal(new[] { "YuanC-KS-App-1", "YuanC-KS-App-2" }, KillSwitchPlanner.AppRuleNames(2));
        Assert.Equal(KillSwitchPlanner.AppRuleNames(2), plan.OfType<AddBlockRule>().Select(x => x.Name));
        Assert.Equal(programs, plan.OfType<AddBlockRule>().Select(x => x.Program));
        var script = Script(plan);
        foreach (var value in programs.Concat(KillSwitchPlanner.NonTunLocalAddresses).Concat(new[] { "-Action Block", "mode", "MpsSvc", "-Enabled True", "ActiveStore", "verifiedAt", "verifyFailed" })) Assert.Contains(value, script);
        Assert.Equal(new[] { "0.0.0.0-126.255.255.255", "128.0.0.0-172.19.0.0", "172.19.0.2-255.255.255.255", "::2-fdfe:dcba:9876::0", "fdfe:dcba:9876::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }, KillSwitchPlanner.NonTunLocalAddresses);
        foreach (var forbidden in new[] { "-DefaultOutboundAction", "Disable-NetFirewallRule", "-Action Allow" }) Assert.DoesNotContain(forbidden, script);
    }

    [Fact]
    public void AppsPatrolChecksEffectiveBlocksWithoutChangingDefaultOrForeignRules()
    {
        var script = Script([new Patrol(KillSwitchPlanner.AppRuleNames(1), EnforceDefaultBlock: false)]);
        Assert.DoesNotContain("-DefaultOutboundAction Block", script); Assert.DoesNotContain("Disable-NetFirewallRule", script);
        foreach (var value in new[] { "MpsSvc", "-Enabled True", "Get-NetFirewallRule -PolicyStore ActiveStore", "'Block'", "missing_rules", "newly_disabled", "exit 3" }) Assert.Contains(value, script);
    }

    [Fact]
    public void PendingModeReadsLegacyAndInvalidState()
    {
        using var temp = new TempDirectory();
        var applier = new KillSwitchApplier(temp.Path);
        Assert.Null(applier.PendingMode);
        File.WriteAllText(applier.StatePath, "{\"mode\":\"apps\"}"); Assert.Equal("apps", applier.PendingMode);
        File.WriteAllText(applier.StatePath, "{}"); Assert.Equal("global", applier.PendingMode);
        File.WriteAllText(applier.StatePath, "{bad"); Assert.Null(applier.PendingMode);
    }

    [Fact]
    public void InvalidPlansAreRejectedBeforeExecution()
    {
        Assert.Throws<ArgumentException>(() => KillSwitchPlanner.PlanApps([]));
        Assert.Throws<ArgumentException>(() => KillSwitchPlanner.PlanApps(Enumerable.Range(1, 33).Select(i => $@"C:\a{i}.exe").ToArray()));
        Assert.Throws<ArgumentException>(() => KillSwitchPlanner.PlanApps(["relative.exe"]));
        Assert.Throws<ArgumentException>(() => Script([new AddBlockRule("Other", RoutingTests.Chrome, ["0.0.0.0/0"])]));
        Assert.Throws<ArgumentException>(() => Script([new AddBlockRule(KillSwitchPlanner.AppPrefix + "1", "relative.exe", ["0.0.0.0/0"])]));
        Assert.Throws<ArgumentException>(() => Script([new AddBlockRule(KillSwitchPlanner.AppPrefix + "1", RoutingTests.Chrome, [])]));
    }
}
