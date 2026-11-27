using System.Diagnostics;
using System.Net;
using System.Text;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class KillSwitchRestoreFastTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.5")];
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    private static string Script(IReadOnlyList<FirewallAction> actions) =>
        KillSwitchPlanner.ToPowerShellScript(actions, "state.json", "audit.json");

    [Fact]
    public void RestoreScriptPutsProfilesBeforeRulesAndEnablesInOneBatch()
    {
        var script = Script([new RestoreProfileDefault()]);
        var profile = script.IndexOf("Set-NetFirewallProfile -Profile $p.Name", StringComparison.Ordinal);
        var enable = script.IndexOf("Enable-NetFirewallRule", StringComparison.Ordinal);
        var delete = script.IndexOf("Remove-Item -LiteralPath $statePath", StringComparison.Ordinal);
        Assert.True(profile >= 0 && enable > profile && delete > enable);
        Assert.Contains("$targets | Enable-NetFirewallRule", script);
        // 批量启用只允许出现一次,不许回到逐条处理。
        Assert.Equal(1, script.Split("Enable-NetFirewallRule", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("-Name $name", script);
    }

    [Fact]
    public void ApplyScriptDisablesForeignRulesInOneBatch()
    {
        var script = Script(KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 8443, KillSwitchMode.Apply));
        Assert.Contains("$foreignRules | Disable-NetFirewallRule", script);
        Assert.DoesNotContain("foreach ($rule in $foreignRules)", script);
        var disable = script.IndexOf("Disable-NetFirewallRule", StringComparison.Ordinal);
        Assert.True(script.IndexOf("Write-State $state", StringComparison.Ordinal) < disable);
        Assert.True(script.LastIndexOf("Write-State $state", StringComparison.Ordinal) > disable);
    }

    [Fact]
    public void FallbackScriptEnablesInOneBatchAndStillRestoresProfilesFirst()
    {
        var script = Script([new RecoverFallback()]);
        Assert.Contains("$targets | Enable-NetFirewallRule", script);
        Assert.Contains("$_.Direction -eq 'Outbound'", script);
        Assert.DoesNotContain("-Name $name", script);
        var profile = script.IndexOf("Set-NetFirewallProfile -Profile $p.Name", StringComparison.Ordinal);
        var enable = script.IndexOf("Enable-NetFirewallRule", StringComparison.Ordinal);
        Assert.True(profile >= 0 && enable > profile);
    }

    [Fact]
    public void GeneratedScriptsParseInWindowsPowerShell()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var directory = new TempDirectory();
        var auth = new AuthEndpoint(IPAddress.Parse("192.0.2.9"), 8443, ProgramPath);
        var statePath = Path.Combine(directory.Path, "killswitch-state.json");
        var auditPath = Path.Combine(directory.Path, "firewall-audit.json");
        var scripts = new[]
        {
            KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 8443, KillSwitchMode.Apply, 443, auth), statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.PlanApps([ProgramPath]), statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.UpdateNode(Ips, ProgramPath, 8443), statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove), statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript([new RecoverFallback()], statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript([new Patrol(KillSwitchPlanner.ExpectedRuleNames(true))], statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript([new Patrol(KillSwitchPlanner.AppRuleNames(1), EnforceDefaultBlock: false)], statePath, auditPath),
            KillSwitchPlanner.ToPowerShellScript([new Audit()], statePath, auditPath)
        };
        var files = new List<string>();
        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);
        for (var i = 0; i < scripts.Length; i++)
        {
            var file = Path.Combine(directory.Path, "script" + i + ".ps1");
            File.WriteAllText(file, scripts[i], utf8);
            files.Add(file);
        }
        var list = string.Join(",", files.Select(file => "'" + file.Replace("'", "''", StringComparison.Ordinal) + "'"));
        var command = "$bad=0; foreach ($f in @(" + list + ")) { $t=$null; $e=$null; "
            + "[System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$t, [ref]$e) | Out-Null; "
            + "if ($e.Count -gt 0) { Write-Output ($f + ': ' + $e[0].Message); $bad++ } }; exit $bad";
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Command", command }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(120000) && process.ExitCode == 0, "脚本语法错误:" + output + error);
    }
    [Fact]
    public async Task ApplyTimeoutThrowsTimeoutExceptionWithFixedMessage()
    {
        using var directory = new TempDirectory();
        var log = new List<string>();
        var applier = new KillSwitchApplier(directory.Path, new HangingRunner(), log: log.Add)
        { ScriptTimeout = TimeSpan.FromMilliseconds(50) };
        var error = await Assert.ThrowsAsync<TimeoutException>(() => applier.ApplyAsync(Ips, ProgramPath, 443));
        Assert.Equal(KillSwitchApplier.ScriptTimedOut, error.Message);
        Assert.Contains(log, line => line.StartsWith("防火墙脚本[套用] 超时，用时 ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RestoreStageTimeoutFallsBackToDegradedRecovery()
    {
        using var directory = new TempDirectory();
        var log = new List<string>();
        var runner = new TimeoutThenSuccessRunner();
        var applier = new KillSwitchApplier(directory.Path, runner, log: log.Add)
        { ScriptTimeout = TimeSpan.FromMilliseconds(50) };
        File.WriteAllText(applier.StatePath, "{}");
        runner.StatePath = applier.StatePath;
        var warning = await applier.RecoverAsync();
        Assert.False(string.IsNullOrWhiteSpace(warning));
        Assert.Equal(2, runner.Calls);
        var recoveryLog = Path.Combine(directory.Path, "killswitch-recovery.log");
        Assert.Contains(File.ReadAllLines(recoveryLog), line => line.EndsWith(" restore timeout", StringComparison.Ordinal));
        var restore = log.FindIndex(line => line.StartsWith("防火墙脚本[启动恢复] 超时", StringComparison.Ordinal));
        var fallback = log.FindIndex(line => line.StartsWith("防火墙脚本[降级恢复] 退出码 0", StringComparison.Ordinal));
        Assert.True(restore >= 0 && fallback > restore);
    }

    [Fact]
    public async Task PatrolKeepsExternalCancelAndTurnsOwnTimeoutIntoTimeoutException()
    {
        using var directory = new TempDirectory();
        var applier = new KillSwitchApplier(directory.Path, new HangingRunner())
        { ScriptTimeout = TimeSpan.FromMilliseconds(50) };
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var error = await Record.ExceptionAsync(() => applier.PatrolAsync([], true, cancelled.Token));
        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.IsNotType<TimeoutException>(error);
        var timeout = await Assert.ThrowsAsync<TimeoutException>(() => applier.PatrolAsync([], true));
        Assert.Equal(KillSwitchApplier.ScriptTimedOut, timeout.Message);
    }

    [Fact]
    public async Task LogRecordsPhaseExitCodeDurationAndSanitizedError()
    {
        using var directory = new TempDirectory();
        var log = new List<string>();
        var applier = new KillSwitchApplier(directory.Path,
            new ResultRunner(new CommandResult(1, "", "失败 203.0.113.9 C:\\Users\\alice\\x")), log: log.Add);
        await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RemoveAsync());
        var line = Assert.Single(log);
        Assert.StartsWith("防火墙脚本[撤销] 退出码 1，用时 ", line);
        Assert.Contains("，错误摘要：", line);
        Assert.Contains("[地址]", line);
        Assert.Contains("[用户]", line);
        Assert.DoesNotContain("203.0.113.9", line);
        Assert.DoesNotContain("alice", line);
    }

    [Fact]
    public async Task SuccessfulRunLogsWithoutErrorSummaryAndPatrolStaysQuiet()
    {
        using var directory = new TempDirectory();
        var log = new List<string>();
        var applier = new KillSwitchApplier(directory.Path,
            new ResultRunner(new CommandResult(0, "{\"reenforced\":[],\"newly_disabled\":[],\"missing_rules\":[]}")), log: log.Add);
        await applier.ApplyAsync(Ips, ProgramPath, 443);
        var line = Assert.Single(log);
        Assert.Contains("防火墙脚本[套用] 退出码 0，用时 ", line);
        Assert.DoesNotContain("错误摘要", line);
        await applier.PatrolAsync([]);
        Assert.DoesNotContain(log, item => item.Contains("防火墙脚本[巡检]", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LogCallbackFailureDoesNotBreakRemove()
    {
        using var directory = new TempDirectory();
        var applier = new KillSwitchApplier(directory.Path, new ResultRunner(new CommandResult(0, "")),
            log: _ => throw new InvalidOperationException("记录失败"));
        await applier.RemoveAsync();
    }

    [Fact]
    public void SanitizeErrorMasksAddressesUserFoldersAndTruncates()
    {
        Assert.Equal("", KillSwitchApplier.SanitizeError(null));
        Assert.Equal("", KillSwitchApplier.SanitizeError("   "));
        Assert.Equal("第一行 | 第二行", KillSwitchApplier.SanitizeError("第一行\r\n第二行"));
        Assert.Equal("[地址] 和 [地址]", KillSwitchApplier.SanitizeError("10.0.0.8 和 203.0.113.9"));
        Assert.Equal(@"D:\Users\[用户]\AppData", KillSwitchApplier.SanitizeError(@"D:\Users\Bob\AppData"));
        var longText = KillSwitchApplier.SanitizeError(new string('x', 700));
        Assert.Equal(601, longText.Length);
        Assert.EndsWith("…", longText);
    }

    [Fact]
    public async Task CommandRunnerReturnsStandardErrorText()
    {
        if (!OperatingSystem.IsWindows()) return;
        var start = new ProcessStartInfo { FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe") };
        start.ArgumentList.Add("/c");
        start.ArgumentList.Add("echo oops 1>&2 & exit 3");
        var result = await new CommandRunner().RunAsync(start);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("oops", result.Error);
    }

    [Fact]
    public async Task WfpInstallAndRemoveAreLogged()
    {
        using var directory = new TempDirectory();
        var log = new List<string>();
        var applier = new KillSwitchApplier(directory.Path, new ResultRunner(new CommandResult(0, "")), new FakeWfp(), log: log.Add);
        await applier.ApplyAsync(Ips, ProgramPath, 443);
        Assert.Contains("过滤层安装：成功", log);
        await applier.RemoveAsync();
        Assert.Contains("过滤层移除：成功", log);
    }

    private sealed class HangingRunner : ICommandRunner
    {
        public async Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return new CommandResult(0, "");
        }
    }

    private sealed class TimeoutThenSuccessRunner : ICommandRunner
    {
        public string? StatePath { get; set; }
        public int Calls { get; private set; }
        public async Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (Calls == 1) await Task.Delay(Timeout.Infinite, cancellationToken);
            if (StatePath is not null && File.Exists(StatePath)) File.Delete(StatePath);
            return new CommandResult(0, "");
        }
    }

    private sealed class ResultRunner(CommandResult result) : ICommandRunner
    {
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default) =>
            Task.FromResult(result);
    }

    private sealed class FakeWfp : IWfpEngine
    {
        public void Install(IReadOnlyList<WfpFilterSpec> filters) { }
        public void Remove() { }
        public IReadOnlyList<string> ListFilterNames() => [];
    }
}
