using System.Net;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchHardenTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.5")];
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    private static IReadOnlyList<FirewallAction> ApplyPlan() =>
        KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 8443, KillSwitchMode.Apply);
    private static string Script(IReadOnlyList<FirewallAction> actions) =>
        KillSwitchPlanner.ToPowerShellScript(actions, "state.json", "audit.json");

    [Fact]
    public void ApplyActionOrderIsExact()
    {
        Assert.Equal(new[] { "SetProfileDefault", "SetProfileDefault", "SetProfileDefault",
            "DisableForeignAllowRules", "AddRule", "AddRule", "AddRule", "AddRule", "AddRule", "AddRule", "VerifyProfiles", "Audit" },
            ApplyPlan().Select(action => action.GetType().Name));
    }

    [Fact]
    public void ApplyRecordsUnionBeforeDisablingOnlyLocalEnabledOutboundAllows()
    {
        var script = Script(ApplyPlan());
        Assert.Contains("$ErrorActionPreference = 'Stop'", script);
        Assert.Contains("Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Direction Outbound -Action Allow", script);
        Assert.Contains("$_.Name -notlike 'YuanC-KS-*'", script);
        Assert.Contains("$state.disabledRules = @(", script);
        Assert.Contains("@($state.disabledRules) + @($foreignRules.Name)", script);
        Assert.Contains("Sort-Object -Unique", script);
        var record = script.IndexOf("$state.disabledRules = @(", StringComparison.Ordinal);
        var write = script.IndexOf("Write-State $state", record, StringComparison.Ordinal);
        var disable = script.IndexOf("Disable-NetFirewallRule", StringComparison.Ordinal);
        Assert.True(record >= 0 && write > record && disable > write);
        Assert.DoesNotContain("foreach ($rule in $foreignRules)", script);
        Assert.Contains("$foreignRules | Disable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable disableError", script);
        Assert.Contains("catch { $disableError = @($_) }", script);
        Assert.Contains("if ($disableError)", script);
        Assert.Contains("$state.disableFailed", script);
        Assert.True(script.IndexOf("Write-State $state", disable, StringComparison.Ordinal) > disable);
        Assert.Contains("Add-Member -NotePropertyName disabledRules", script);
        Assert.DoesNotContain("-Direction Inbound", script);
        Assert.DoesNotContain("-Action Block", script);
    }

    [Fact]
    public void UnmanagedRulesAreActiveAllowsAbsentFromAllPersistentRules()
    {
        var script = Script(ApplyPlan());
        Assert.Contains("$persistentNames = @(Get-NetFirewallRule -PolicyStore PersistentStore | Select-Object -ExpandProperty Name)", script);
        Assert.Contains("Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow", script);
        Assert.Contains("$persistentNames -notcontains $_.Name", script);
        Assert.Contains("Name = $r.Name; Program = $app.Program", script);
        Assert.Contains("$state.unmanagedRules = @(Read-UnmanagedRules)", script);
        Assert.DoesNotContain("$state.unmanagedRules | Disable-NetFirewallRule", script);
    }

    [Fact]
    public void RemoveRestoresProfilesBeforeRulesAndDeletingSnapshotWithLegacyGuard()
    {
        var plan = KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove);
        Assert.Equal(new[] { "RemoveRulesByPrefix", "RestoreProfileDefault" }, plan.Select(action => action.GetType().Name));
        Assert.DoesNotContain(plan, action => action.GetType().Name == "DisableForeignAllowRules");
        var script = Script(plan);
        Assert.DoesNotContain("Disable-NetFirewallRule", script);
        Assert.Contains("if ($null -ne $state.disabledRules)", script);
        Assert.Contains("foreach ($name in @($state.disabledRules))", script);
        Assert.DoesNotContain("-PolicyStore PersistentStore -Name $name", script);
        Assert.Contains("$targets | Enable-NetFirewallRule", script);
        Assert.Contains("Enable-NetFirewallRule -ErrorAction SilentlyContinue", script);
        Assert.Contains("catch { $enableError = @($_) }", script);
        Before(script, "Set-NetFirewallProfile -Profile $p.Name", "Enable-NetFirewallRule");
        Before(script, "Enable-NetFirewallRule", "Remove-Item -LiteralPath $statePath");
        Before(script, "Set-NetFirewallProfile -Profile $p.Name", "Remove-Item -LiteralPath $statePath");
        Assert.Contains("YUANC-NO-RECORD=windows_default", script);
    }

    [Fact]
    public void UpdateNodeRemainsRemoveThenTwoNodeAllowsWithoutStateChanges()
    {
        var plan = KillSwitchPlanner.UpdateNode(Ips, ProgramPath, 8443);
        Assert.Equal(new[] { "RemoveRulesByPrefix", "AddRule", "AddRule" }, plan.Select(action => action.GetType().Name));
        Assert.Equal(KillSwitchPlanner.NodePrefix, Assert.IsType<RemoveRulesByPrefix>(plan[0]).Prefix);
        Assert.Equal(new[] { "YuanC-KS-Node-Tcp", "YuanC-KS-Node-Udp" }, plan.OfType<AddRule>().Select(rule => rule.Name));
        var script = Script(plan);
        Assert.DoesNotContain("Disable-NetFirewallRule", script);
        Assert.DoesNotContain("Enable-NetFirewallRule", script);
        Assert.DoesNotContain("Set-NetFirewallProfile", script);
    }

    [Fact]
    public void OnlyProjectRulesCanBeRemovedAndEnableIsExclusiveToRestore()
    {
        var plans = new[] { ApplyPlan(), KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove),
            KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Audit), KillSwitchPlanner.UpdateNode(Ips, ProgramPath, 8443) };
        foreach (var plan in plans)
        {
            var script = Script(plan);
            Assert.DoesNotContain("Set-NetFirewallRule", script);
            Assert.All(script.Split('\n').Where(line => line.Contains("Remove-NetFirewallRule", StringComparison.Ordinal)),
                line => Assert.Matches("^Get-NetFirewallRule -Name 'YuanC-KS-[^']+' -ErrorAction SilentlyContinue \\| Remove-NetFirewallRule\\r?$", line));
            if (!plan.OfType<RestoreProfileDefault>().Any()) Assert.DoesNotContain("Enable-NetFirewallRule", script);
        }
    }

    [Fact]
    public void AuditWritesObjectWithBothArraysAndTimestampAndSupportsMissingState()
    {
        var script = Script([new Audit()]);
        Assert.Contains("foreign_allow_rules = @($foreignAllowRules)", script);
        Assert.Contains("unmanaged_rules = @($unmanagedRules)", script);
        Assert.Contains("generated_at = [DateTime]::UtcNow.ToString('o')", script);
        Assert.Contains("if (Test-Path -LiteralPath $statePath)", script);
        Assert.Contains("$auditState.unmanagedRules", script);
        Assert.Contains("$unmanagedRules = @(Read-UnmanagedRules)", script);
        Assert.Contains("ConvertTo-Json -InputObject $audit", script);
        Assert.DoesNotContain("Disable-NetFirewallRule", script);
        Assert.DoesNotContain("Enable-NetFirewallRule", script);
        Assert.DoesNotContain("Remove-NetFirewallRule", script);
        Assert.DoesNotContain("Write-State $state", script);
    }

    private static void Before(string script, string first, string second)
    {
        var firstIndex = script.IndexOf(first, StringComparison.Ordinal);
        var secondIndex = script.IndexOf(second, StringComparison.Ordinal);
        Assert.True(firstIndex >= 0 && secondIndex > firstIndex, $"Expected {first} before {second}");
    }
}
