using System.Text.RegularExpressions;
using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class EnvironmentPlannerTests
{
    [Fact]
    public void ApplyRecordsOriginalBeforeAnySystemWriteAndUsesOnlyApprovedPolicies()
    {
        var script = EnvironmentPlanner.ApplyScript(new("AUS Eastern Standard Time", ["en-AU", "en"]), "state's.json");
        var recorded = script.IndexOf("Write-State $state", StringComparison.Ordinal);
        Assert.True(recorded >= 0);
        Assert.True(recorded < script.IndexOf("tzutil /s", StringComparison.Ordinal));
        Assert.True(recorded < script.IndexOf("Set-ItemProperty", StringComparison.Ordinal));
        foreach (var value in new[] { "tzautoupdate", "-Value 4", "exit 4", "ForcedLanguages", "WebRtcIPHandling",
            "DefaultGeolocationSetting", "DefinePreferredLanguages", "WebRtcLocalhostIpHandling", "default_public_interface_only",
            "DnsOverHttpsMode", "DnsOverHttpsTemplates", "'secure'", "'https://1.1.1.1/dns-query'",
            @"HKLM:\SOFTWARE\Policies\Google\Chrome", @"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            "AUS Eastern Standard Time", "'en-AU'", "'en'", "'en-AU,en'", "state''s.json" }) Assert.Contains(value, script);
        Assert.Contains("$original = $previous.original", script);
        Assert.Contains("applied = $false", script);
        Assert.Contains("$state.applied = $true", script);
        Assert.Contains("verify_failed", script);
        Assert.Contains("policies_written=10", script);
        foreach (var browser in new[] { "$chromeKey", "$edgeKey" })
        foreach (var policy in new[] { "DnsOverHttpsMode -Value 'secure'", "DnsOverHttpsTemplates -Value 'https://1.1.1.1/dns-query'" })
        {
            var write = script.IndexOf($"Set-ItemProperty -LiteralPath {browser} -Name {policy} -Type String", StringComparison.Ordinal);
            Assert.True(write > recorded);
            Assert.True(write < script.IndexOf("$state.applied = $true", StringComparison.Ordinal));
        }
        Assert.Contains("Move-Item -LiteralPath $temp -Destination $statePath -Force", script);
        Assert.DoesNotContain("ApplicationLocaleValue", script);
        Assert.DoesNotContain("-Recurse", script);
    }

    [Fact]
    public void RestoreIsBoundedAndDeletesRecordOnlyAfterRestoring()
    {
        var script = EnvironmentPlanner.RestoreScript("state.json");
        Assert.Contains("tzutil /s", script);
        Assert.Contains("Remove-ItemProperty", script);
        Assert.Contains("Remove-Item -LiteralPath $statePath", script);
        Assert.Equal(3, Regex.Matches(script, @"\bRemove-Item\s").Count);
        Assert.DoesNotContain("-Recurse", script);
        Assert.True(script.LastIndexOf("Remove-Item -LiteralPath $statePath", StringComparison.Ordinal) >
            script.LastIndexOf("Set-ItemProperty", StringComparison.Ordinal));
        Assert.Contains("$LASTEXITCODE", script);
    }

    [Fact]
    public void InspectIsReadOnlyAndContainsAllCurrentEnvironmentFields()
    {
        var script = EnvironmentPlanner.InspectScript();
        foreach (var field in new[] { "time_zone", "tzautoupdate_start", "chrome", "edge", "forced_languages", "ConvertTo-Json -Compress", "DnsOverHttpsMode", "DnsOverHttpsTemplates" })
            Assert.Contains(field, script);
        foreach (var command in new[] { "Set-Item", "New-Item", "Remove-Item", "Stop-Service", "Start-Service", "tzutil /s", "Write-State" })
            Assert.DoesNotContain(command, script);
    }

    [Fact]
    public void RestoreContinuesAfterStepFailureAndKeepsRecordOnFailure()
    {
        var script = EnvironmentPlanner.RestoreScript("state.json");
        Assert.Contains("$failed = @()", script);
        Assert.True(Regex.Matches(script, @"\$failed \+=").Count >= 6);
        Assert.Contains("restore_failed", script);
        Assert.Contains("$failed -join", script);
        var failure = script.IndexOf("if ($failed.Count -gt 0)", StringComparison.Ordinal);
        Assert.True(failure >= 0);
        Assert.True(failure < script.IndexOf("Remove-Item -LiteralPath $statePath", StringComparison.Ordinal));
        Assert.Equal(3, Regex.Matches(script, @"\bRemove-Item\s").Count);
        Assert.DoesNotContain("-Recurse", script);
        var zone = script.IndexOf("tzutil /s", StringComparison.Ordinal);
        var caught = script.IndexOf("catch {", zone, StringComparison.Ordinal);
        Assert.True(caught > zone);
        Assert.True(caught < script.IndexOf("-Name Start", StringComparison.Ordinal));
        Assert.True(script.IndexOf("try {", caught, StringComparison.Ordinal) < script.IndexOf("-Name Start", StringComparison.Ordinal));
    }

    [Fact]
    public void RestoreSkipsValuesAbsentFromLegacyRecord()
    {
        var script = EnvironmentPlanner.RestoreScript("state.json");
        Assert.Matches(@"if\s*\(\$null -eq \$entry\)\s*\{\s*continue\s*\}", script);
        Assert.Contains("$entry.kind -notin @('String','DWord')", script);
        Assert.Contains("throw '浏览器策略恢复记录无效。'", script);
    }

    [Theory]
    [InlineData("bad'id")]
    [InlineData("")]
    [InlineData("AUS Eastern Standard Time\n")]
    public void InvalidTimeZoneIsRejected(string id) => Assert.Throws<ArgumentException>(() => new EnvironmentTarget(id, ["en-AU"]));

    [Fact]
    public void OversizeTimeZoneAndInvalidLanguagesAreRejected()
    {
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget(new string('a', 65), ["en"]));
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget("UTC", ["zh_CN"]));
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget("UTC", []));
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget("UTC", Enumerable.Repeat("en", 9).ToArray()));
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget("UTC", ["en\n"]));
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget(null!, ["en"]));
        Assert.Throws<ArgumentException>(() => new EnvironmentTarget("UTC", null!));
    }
}
