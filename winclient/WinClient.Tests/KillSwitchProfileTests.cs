using System.Diagnostics;
using System.Net;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchProfileTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.5")];
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    private static IReadOnlyList<FirewallAction> ApplyPlan() =>
        KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 8443, KillSwitchMode.Apply);
    private static string Script(IReadOnlyList<FirewallAction> actions) =>
        KillSwitchPlanner.ToPowerShellScript(actions, "state.json", "audit.json");

    [Fact]
    public void ApplySavesEnabledForcesAllProfilesAndVerifiesBeforeAudit()
    {
        var script = Script(ApplyPlan());
        Assert.Contains("Select-Object Name,DefaultOutboundAction,Enabled", script);
        Assert.Contains("Enabled = [string]$_.Enabled", script);
        var setters = script.Split('\n').Where(line => line.StartsWith("Set-NetFirewallProfile ", StringComparison.Ordinal)).ToArray();
        Assert.Equal(3, setters.Length);
        foreach (var profile in new[] { "Domain", "Private", "Public" })
            Assert.Contains("Set-NetFirewallProfile -Enabled True -DefaultOutboundAction Block -Profile '" + profile + "'", script);
        var verify = script.IndexOf("$effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultOutboundAction)", StringComparison.Ordinal);
        Assert.True(verify > script.LastIndexOf("New-NetFirewallRule", StringComparison.Ordinal));
        Assert.Contains("$effective.Count -ne 3", script);
        Assert.Contains("[string]$_.Enabled -ne 'True'", script);
        Assert.Contains("[string]$_.DefaultOutboundAction -ne 'Block'", script);
        Assert.Contains("$state.verifyFailed = @($bad)", script);
        Assert.Contains("$state.verifyFailed = @()", script);
        Assert.Contains("$state.verifiedAt = [DateTime]::UtcNow.ToString('o')", script);
        Assert.Contains("Add-Member -NotePropertyName verifyFailed", script);
        Assert.Contains("Add-Member -NotePropertyName verifiedAt", script);
        var exit = script.IndexOf("exit 3", StringComparison.Ordinal);
        Assert.True(exit > verify);
        Assert.True(script.IndexOf("Write-State $state", verify, StringComparison.Ordinal) < exit);
        Assert.True(exit < script.IndexOf("ConvertTo-Json -InputObject $audit", StringComparison.Ordinal));
        Assert.Contains("profiles_effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultOutboundAction)", script);
    }

    [Fact]
    public void ApplyActionOrderIsExact()
    {
        Assert.Equal(new[] { "SetProfileDefault", "SetProfileDefault", "SetProfileDefault",
            "DisableForeignAllowRules", "AddRule", "AddRule", "AddRule", "AddRule", "AddRule", "AddRule", "VerifyProfiles", "Audit" },
            ApplyPlan().Select(action => action.GetType().Name));
    }

    [Fact]
    public void RemoveRestoresEnabledOnlyWhenRecordedAndRejectsInvalidEnabled()
    {
        var script = Script(KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove));
        Assert.Contains("$null -ne $p.PSObject.Properties['Enabled']", script);
        Assert.Contains("$p.Enabled -notin @('True','False')", script);
        Assert.Contains("防火墙恢复记录无效", script);
        Assert.Contains("if ($null -ne $p.PSObject.Properties['Enabled']) { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction } else { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction }", script);
    }

    [Fact]
    public void FallbackRestoresRecordedEnabledButDoesNotGuessForWindowsDefaults()
    {
        var script = Script([new RecoverFallback()]);
        Assert.Contains("$p.Enabled -notin @('True','False')", script);
        Assert.Contains("{ $recordValid = $false }", script);
        Assert.Contains("if ($null -ne $p.PSObject.Properties['Enabled']) { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction } else { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction }", script);
        var lines = script.Replace("\r\n", "\n").Split('\n');
        var defaultIndex = Array.FindIndex(lines, line => line.Contains("$profilesApplied = 'windows_default'", StringComparison.Ordinal));
        Assert.True(defaultIndex > 0);
        Assert.Equal("  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow", lines[defaultIndex - 1]);
        Assert.DoesNotContain("-Enabled", lines[defaultIndex - 1]);
    }

    [Fact]
    public async Task VerificationExitCodeHasSpecificExceptionAndChineseExplanation()
    {
        using var directory = new TempDirectory();
        var applier = new KillSwitchApplier(directory.Path, new ExitRunner(3));
        var error = await Assert.ThrowsAsync<FirewallIneffectiveException>(() => applier.ApplyAsync(Ips, ProgramPath, 8443));
        Assert.Equal(3, KillSwitchApplier.VerifyFailedExitCode);
        Assert.Contains("防火墙", error.Message);
        Assert.Contains("策略", error.Message);
        Assert.Contains("已拒绝连接", error.Message);
    }

    [Fact]
    public async Task OtherFailureKeepsExactOriginalExceptionTypeAndMessage()
    {
        using var directory = new TempDirectory();
        var applier = new KillSwitchApplier(directory.Path, new ExitRunner(1));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => applier.ApplyAsync(Ips, ProgramPath, 8443));
        Assert.IsNotType<FirewallIneffectiveException>(error);
        Assert.Equal("防火墙操作失败，恢复记录已保留，请联系管理员。", error.Message);
    }

    private sealed class ExitRunner(int exitCode) : ICommandRunner
    {
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default) =>
            Task.FromResult(new CommandResult(exitCode, ""));
    }
}
