using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

/// <summary>没有恢复记录时撤销断网保护的证据判定、脚本真跑桩函数、执行器警告与测试包外壳转发。</summary>
public sealed class KillSwitchNoRecordTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.5")];
    private static string ProgramPath => Path.GetFullPath("sing-box.exe");
    private const string Evidence = "$hadGlobalRules = @(Get-NetFirewallRule -Name 'YuanC-KS-*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'YuanC-KS-App-*' }).Count -gt 0";
    private const string DeleteRules = "Get-NetFirewallRule -Name 'YuanC-KS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule";

    private static string Script(IReadOnlyList<FirewallAction> actions, string statePath, string auditPath) =>
        KillSwitchPlanner.ToPowerShellScript(actions, statePath, auditPath);

    [Fact]
    public void RemoveScriptReadsEvidenceBeforeDeletingRules()
    {
        var remove = Script(KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove), "state.json", "audit.json");
        Assert.Contains(Evidence, remove);
        var evidenceAt = remove.IndexOf(Evidence, StringComparison.Ordinal);
        var deleteAt = remove.IndexOf(DeleteRules, StringComparison.Ordinal);
        Assert.True(evidenceAt >= 0 && deleteAt > evidenceAt, "证据行要在删规则之前");
        var apply = Script(KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 8443, KillSwitchMode.Apply), "state.json", "audit.json");
        Assert.DoesNotContain("$hadGlobalRules", apply);
        var update = Script(KillSwitchPlanner.UpdateNode(Ips, ProgramPath, 8443), "state.json", "audit.json");
        Assert.DoesNotContain("$hadGlobalRules", update);
    }

    [Fact]
    public void NoRecordBranchOnlyTouchesBlockedProfilesWithGlobalEvidence()
    {
        if (!OperatingSystem.IsWindows()) return;
        var script = Script(KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove), "state.json", "audit.json");
        foreach (Match match in Regex.Matches(script, "[A-Za-z]+-NetFirewall[A-Za-z]+"))
            Assert.Contains("function " + match.Value, Stubs("", ""));
        using var directory = new TempDirectory();
        var statePath = Path.Combine(directory.Path, "missing-killswitch-state.json");
        var auditPath = Path.Combine(directory.Path, "firewall-audit.json");
        var generated = Script(KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove), statePath, auditPath);

        var blocked = "Domain=Block,Private=Allow,Public=Block";
        var (exit, output, error) = RunScript(Stubs(
            "[pscustomobject]@{ Name = 'YuanC-KS-Tun' }, [pscustomobject]@{ Name = 'YuanC-KS-App-1' }",
            ProfilesText(blocked)) + generated);
        var lines = output.Replace("\r\n", "\n").Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
        Assert.True(exit == 0, "脚本退出码不是 0:" + output + error);
        Assert.Contains("YUANC-NO-RECORD=windows_default", lines);
        Assert.Contains("SET:Domain,Public:Allow", lines);
        Assert.DoesNotContain(lines, line => line.StartsWith("SET:", StringComparison.Ordinal) && line.Contains("Private", StringComparison.Ordinal));

        (exit, output, error) = RunScript(Stubs(
            "[pscustomobject]@{ Name = 'YuanC-KS-App-1' }", ProfilesText("Domain=Block,Private=Block,Public=Block")) + generated);
        lines = output.Replace("\r\n", "\n").Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
        Assert.True(exit == 0, "脚本退出码不是 0:" + output + error);
        Assert.Contains("YUANC-NO-RECORD=untouched", lines);
        Assert.DoesNotContain(lines, line => line.StartsWith("SET:", StringComparison.Ordinal));

        (exit, output, error) = RunScript(Stubs("@()", ProfilesText("Domain=Block,Private=Block,Public=Block")) + generated);
        lines = output.Replace("\r\n", "\n").Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
        Assert.True(exit == 0, "脚本退出码不是 0:" + output + error);
        Assert.Contains("YUANC-NO-RECORD=untouched", lines);
        Assert.DoesNotContain(lines, line => line.StartsWith("SET:", StringComparison.Ordinal));

        (exit, output, error) = RunScript(Stubs(
            "[pscustomobject]@{ Name = 'YuanC-KS-Tun' }", ProfilesText("Domain=Allow,Private=Allow,Public=Allow")) + generated);
        lines = output.Replace("\r\n", "\n").Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
        Assert.True(exit == 0, "脚本退出码不是 0:" + output + error);
        Assert.Contains("YUANC-NO-RECORD=untouched", lines);
        Assert.DoesNotContain(lines, line => line.StartsWith("SET:", StringComparison.Ordinal));
    }

    /// <summary>真跑脚本用的桩函数:防火墙命令全部改成本地函数,返回场景数据,不会碰到真系统。</summary>
    private static string Stubs(string rules, string profiles) =>
        "$scenarioRules = @(" + rules + ")\n"
        + "$scenarioProfiles = @(" + profiles + ")\n"
        + "function Get-NetFirewallRule { return $scenarioRules }\n"
        + "function Remove-NetFirewallRule { Write-Output 'REMOVE-CALLED' }\n"
        + "function Enable-NetFirewallRule { Write-Output 'ENABLE-CALLED' }\n"
        + "function Get-NetFirewallProfile { return $scenarioProfiles }\n"
        + "function Set-NetFirewallProfile { param($Profile, $Enabled, $DefaultOutboundAction) Write-Output ('SET:' + ($Profile -join ',') + ':' + $DefaultOutboundAction) }\n";

    private static string ProfilesText(string spec) =>
        string.Join(", ", spec.Split(',').Select(pair =>
        {
            var parts = pair.Split('=');
            return "[pscustomobject]@{ Name = '" + parts[0] + "'; DefaultOutboundAction = '" + parts[1] + "' }";
        }));

    private static (int ExitCode, string Output, string Error) RunScript(string script)
    {
        using var process = new Process { StartInfo = KillSwitchApplier.CreateStartInfo(script) };
        if (!process.Start()) return (-1, "", "无法启动 PowerShell。");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(10000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            return (-1, output.Result, error.Result + " 超时");
        }
        return (process.ExitCode, output.Result, error.Result);
    }

    [Fact]
    public void NoRecordScriptParsesInWindowsPowerShell()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var directory = new TempDirectory();
        var statePath = Path.Combine(directory.Path, "killswitch-state.json");
        var auditPath = Path.Combine(directory.Path, "firewall-audit.json");
        var file = Path.Combine(directory.Path, "remove.ps1");
        File.WriteAllText(file, Script(KillSwitchPlanner.Plan([], "", "", 0, KillSwitchMode.Remove), statePath, auditPath),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        var quoted = "'" + file.Replace("'", "''", StringComparison.Ordinal) + "'";
        var command = "$t=$null; $e=$null; [System.Management.Automation.Language.Parser]::ParseFile(" + quoted
            + ", [ref]$t, [ref]$e) | Out-Null; if ($e.Count -gt 0) { Write-Output $e[0].Message; exit 1 }; exit 0";
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
    public async Task ApplierSetsWarningAndRecoveryLineOnWindowsDefault()
    {
        using var directory = new TempDirectory();
        var applier = new KillSwitchApplier(directory.Path,
            new ScriptedRunner(new CommandResult(0, "YUANC-NO-RECORD=windows_default\r\n")));
        await applier.RemoveAsync();
        Assert.Equal(KillSwitchApplier.NoRecordRemoveWarning, applier.LastRemoveWarning);
        var log = Path.Combine(directory.Path, "killswitch-recovery.log");
        Assert.True(File.Exists(log), "没有写 killswitch-recovery.log");
        Assert.Contains(File.ReadAllLines(log), line => line.EndsWith(" remove no_record windows_default", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ApplierClearsWarningWhenUntouchedOrRecordPresent()
    {
        using var directory = new TempDirectory();
        var applier = new KillSwitchApplier(directory.Path, new ScriptedRunner(
            new CommandResult(0, "YUANC-NO-RECORD=windows_default\r\n"),
            new CommandResult(0, "YUANC-NO-RECORD=untouched\r\n"),
            new CommandResult(0, ""),
            new CommandResult(1, "")));
        await applier.RemoveAsync();
        Assert.Equal(KillSwitchApplier.NoRecordRemoveWarning, applier.LastRemoveWarning);
        await applier.RemoveAsync();
        Assert.Null(applier.LastRemoveWarning);
        await applier.RemoveAsync();
        Assert.Null(applier.LastRemoveWarning);
        await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RemoveAsync());
        Assert.Null(applier.LastRemoveWarning);
    }

    [Fact]
    public async Task DisabledKillSwitchForwardsRemoveWarning()
    {
        var inner = new FakeInner { HasPendingState = false, LastRemoveWarning = "记录丢失警告" };
        var disabled = new DisabledKillSwitch(inner);
        await disabled.RemoveAsync();
        Assert.Equal(0, inner.Removes);
        Assert.Null(disabled.LastRemoveWarning);
        inner.HasPendingState = true;
        await disabled.RemoveAsync();
        Assert.Equal(1, inner.Removes);
        Assert.Equal("记录丢失警告", disabled.LastRemoveWarning);
    }

    private sealed class ScriptedRunner(params CommandResult[] results) : ICommandRunner
    {
        private readonly Queue<CommandResult> results = new(results);
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
            => Task.FromResult(results.Count == 0 ? new CommandResult(0, "") : results.Dequeue());
    }

    private sealed class FakeInner : IKillSwitch
    {
        public bool HasPendingState { get; set; }
        public string? LastRemoveWarning { get; set; }
        public int Removes { get; private set; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null) => Task.CompletedTask;
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port) => Task.CompletedTask;
        public Task RemoveAsync() { Removes++; return Task.CompletedTask; }
        public Task<string?> RecoverAsync() => Task.FromResult<string?>(null);
    }
}
