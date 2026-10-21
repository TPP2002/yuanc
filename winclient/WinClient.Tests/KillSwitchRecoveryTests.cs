using System.Diagnostics;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchRecoveryTests
{
    [Fact]
    public void FallbackArchivesBeforeChangingProfilesAndOnlyRemovesProjectRules()
    {
        var script = KillSwitchPlanner.ToPowerShellScript([new RecoverFallback()], "state.json", "audit.json");
        var archive = script.IndexOf("Copy-Item -LiteralPath $statePath", StringComparison.Ordinal);
        Assert.Contains("killswitch-state.failed-", script);
        Assert.True(archive >= 0 && archive < script.IndexOf("Set-NetFirewallProfile", StringComparison.Ordinal));
        Assert.Contains("-Filter 'killswitch-state.failed-*.json'", script);
        Assert.Contains("Sort-Object Name -Descending | Select-Object -Skip 4", script);
        Assert.True(script.IndexOf("Select-Object -Skip 4", StringComparison.Ordinal) < archive);
        Assert.Contains("Remove-Item -LiteralPath $_.FullName", script);
        Assert.Contains("Copy-Item -LiteralPath $statePath -Destination $archivePath -ErrorAction Stop", script);
        Assert.Contains("Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop", script);
        var deleteState = script.IndexOf("Remove-Item -LiteralPath $statePath", StringComparison.Ordinal);
        Assert.True(deleteState > script.IndexOf("Move-Item -LiteralPath $recoveryTemp -Destination $recoveryPath -Force", StringComparison.Ordinal));
        Assert.True(deleteState > script.IndexOf("killswitch-recovery.json", StringComparison.Ordinal));
        Assert.EndsWith("if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath -ErrorAction Stop }\nexit 0", script.Replace("\r\n", "\n").TrimEnd());
        Assert.Contains("-DefaultOutboundAction Allow", script);
        Assert.Contains("Enable-NetFirewallRule -ErrorAction SilentlyContinue", script);
        Assert.Contains("killswitch-recovery.json", script);
        Assert.Contains("windows_default", script);
        Assert.DoesNotContain("Disable-NetFirewallRule", script);
        Assert.DoesNotContain("New-NetFirewallRule", script);
        Assert.DoesNotContain("-Direction Inbound", script);
        var removals = script.Split('\n').Where(line => line.Contains("Remove-NetFirewallRule", StringComparison.Ordinal)).ToArray();
        Assert.NotEmpty(removals);
        Assert.All(removals, line => Assert.Matches("^Get-NetFirewallRule -Name 'YuanC-KS-[^']+' -ErrorAction SilentlyContinue \\| Remove-NetFirewallRule\\r?$", line));
    }

    [Fact]
    public async Task FallbackWarningSurvivesSecondStartupRecoveryWithoutSnapshot()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(1, 0);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "损坏的记录");
        runner.OnCall = call => { if (call == 2) File.Delete(applier.StatePath); };
        var warning = await applier.RecoverAsync();
        Assert.False(string.IsNullOrWhiteSpace(warning));
        Assert.Equal(warning, applier.LastRecoveryWarning);
        Assert.Equal(2, runner.Calls);
        Assert.Equal(warning, await applier.RecoverAsync());
        Assert.Equal(2, runner.Calls);
        Assert.Contains("killswitch-state.failed-", runner.Scripts[1]);
    }

    [Fact]
    public async Task BothFailuresThrowAndAppendOneLogLinePerStage()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(1, 1);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "{}");
        var log = Path.Combine(directory.Path, "killswitch-recovery.log");
        File.WriteAllText(log, "原有记录" + Environment.NewLine);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RecoverAsync());
        Assert.Equal("防火墙操作失败，恢复记录已保留，请联系管理员。", error.Message);
        Assert.Null(applier.LastRecoveryWarning);
        Assert.Equal(2, runner.Calls);
        Assert.True(File.Exists(applier.StatePath));
        var lines = File.ReadAllLines(log);
        Assert.Equal(3, lines.Length);
        Assert.Equal("原有记录", lines[0]);
        Assert.Contains("restore", lines[1]);
        Assert.Contains("fallback", lines[2]);
        Assert.All(lines.Skip(1), line => Assert.Matches(@"^\d{4}-\d{2}-\d{2}T.*Z .*1", line));
    }

    [Fact]
    public async Task StrictRecoverySuccessReturnsNullAndRunsOnce()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(0);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "{}");
        Assert.Null(await applier.RecoverAsync());
        Assert.Null(applier.LastRecoveryWarning);
        Assert.Equal(1, runner.Calls);
        Assert.Equal(KillSwitchPlanner.ToPowerShellScript(
            [new RemoveRulesByPrefix(KillSwitchPlanner.Prefix), new RestoreProfileDefault()],
            applier.StatePath, applier.AuditPath), Assert.Single(runner.Scripts));
    }

    [Fact]
    public async Task MissingSnapshotDoesNotRunAnyCommand()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner();
        var applier = new KillSwitchApplier(directory.Path, runner);
        Assert.Null(await applier.RecoverAsync());
        Assert.Null(applier.LastRecoveryWarning);
        Assert.Equal(0, runner.Calls);
    }

    [Fact]
    public async Task CleanRecoveryClearsPreviousWarning()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(1, 0, 0);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "{}");
        runner.OnCall = call => { if (call == 2) File.Delete(applier.StatePath); };
        Assert.NotNull(await applier.RecoverAsync());
        File.WriteAllText(applier.StatePath, "{}");
        Assert.Null(await applier.RecoverAsync());
        Assert.Null(applier.LastRecoveryWarning);
        Assert.Equal(3, runner.Calls);
    }

    [Fact]
    public async Task MissingSnapshotAfterStrictFailureStillThrowsWithoutFallback()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(1);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "{}");
        runner.OnCall = _ => File.Delete(applier.StatePath);
        await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RecoverAsync());
        Assert.Equal(1, runner.Calls);
        Assert.Null(applier.LastRecoveryWarning);
    }

    [Fact]
    public async Task FailedFallbackAfterArchivingStillNeedsManualOnControllerRetry()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(1, 1, 1, 1);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "损坏的记录");
        // 模拟降级脚本已成功归档，随后恢复配置或写证据失败。
        runner.OnCall = call => { if (call == 2 || call == 4) File.Copy(applier.StatePath,
            Path.Combine(directory.Path, $"killswitch-state.failed-20261022T00000{call}Z.json")); };
        // 对应 CreateAsync 的首次恢复：捕获异常后继续创建控制器。
        await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RecoverAsync());
        Assert.True(File.Exists(applier.StatePath));
        Assert.Null(applier.LastRecoveryWarning);
        var order = new List<string>();
        using var controller = new ClientController(null, applier,
            new PairingTests.FakeTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Contains("恢复记录已保留", controller.Snapshot.Message);
        Assert.Equal(4, runner.Calls);
        Assert.True(File.Exists(applier.StatePath));
        Assert.Null(applier.LastRecoveryWarning);
    }

    [Fact]
    public async Task LogWriteFailureDoesNotPreventFallback()
    {
        using var directory = new TempDirectory();
        var runner = new RecoveryRunner(1, 0);
        var applier = new KillSwitchApplier(directory.Path, runner);
        File.WriteAllText(applier.StatePath, "{}");
        Directory.CreateDirectory(Path.Combine(directory.Path, "killswitch-recovery.log"));
        Assert.NotNull(await applier.RecoverAsync());
        Assert.Equal(2, runner.Calls);
    }

    private sealed class RecoveryRunner(params int[] exitCodes) : ICommandRunner
    {
        public int Calls { get; private set; }
        public List<string> Scripts { get; } = [];
        public Action<int>? OnCall { get; set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            Scripts.Add(startInfo.ArgumentList.Last());
            Calls++;
            OnCall?.Invoke(Calls);
            return Task.FromResult(new CommandResult(exitCodes[Calls - 1], ""));
        }
    }
}
