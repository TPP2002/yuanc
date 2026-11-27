"""防火墙脚本提速单 yc-killswitch-restore-fast-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
PLANNER = WIN / "WinClient.Core/Firewall/KillSwitchPlanner.cs"
APPLIER = WIN / "WinClient.Core/Firewall/KillSwitchApplier.cs"
RUNNER = WIN / "WinClient.Core/Firewall/CommandRunner.cs"
HARDEN = WIN / "WinClient.Tests/KillSwitchHardenTests.cs"
FAST = WIN / "WinClient.Tests/KillSwitchRestoreFastTests.cs"
ALLOWED = {
    "winclient/WinClient.Core/Firewall/KillSwitchPlanner.cs",
    "winclient/WinClient.Core/Firewall/KillSwitchApplier.cs",
    "winclient/WinClient.Core/Firewall/CommandRunner.cs",
    "winclient/WinClient.Tests/KillSwitchHardenTests.cs",
    "winclient/WinClient.Tests/KillSwitchRestoreFastTests.cs",
}
BATCH_ENABLE = "$targets | Enable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable enableError"
BATCH_DISABLE = "$foreignRules | Disable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable disableError"
LOOKUP = "New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)"
SLOW_LOOKUP = "-PolicyStore PersistentStore -Name $name"
PHASES = ["套用", "套用指定程序", "换节点", "撤销", "巡检", "启动恢复", "降级恢复"]
NEW_TESTS = [
    "RestoreScriptPutsProfilesBeforeRulesAndEnablesInOneBatch",
    "ApplyScriptDisablesForeignRulesInOneBatch",
    "FallbackScriptEnablesInOneBatchAndStillRestoresProfilesFirst",
    "GeneratedScriptsParseInWindowsPowerShell",
    "ApplyTimeoutThrowsTimeoutExceptionWithFixedMessage",
    "RestoreStageTimeoutFallsBackToDegradedRecovery",
    "PatrolKeepsExternalCancelAndTurnsOwnTimeoutIntoTimeoutException",
    "LogRecordsPhaseExitCodeDurationAndSanitizedError",
    "SuccessfulRunLogsWithoutErrorSummaryAndPatrolStaysQuiet",
    "LogCallbackFailureDoesNotBreakRemove",
    "SanitizeErrorMasksAddressesUserFoldersAndTruncates",
    "CommandRunnerReturnsStandardErrorText",
    "WfpInstallAndRemoveAreLogged",
]
HARDEN_TESTS = [
    "ApplyActionOrderIsExact",
    "ApplyRecordsUnionBeforeDisablingOnlyLocalEnabledOutboundAllows",
    "UnmanagedRulesAreActiveAllowsAbsentFromAllPersistentRules",
    "RemoveRestoresProfilesBeforeRulesAndDeletingSnapshotWithLegacyGuard",
    "UpdateNodeRemainsRemoveThenTwoNodeAllowsWithoutStateChanges",
    "OnlyProjectRulesCanBeRemovedAndEnableIsExclusiveToRestore",
    "AuditWritesObjectWithBothArraysAndTimestampAndSupportsMissingState",
]
# 这两个既有用例里不许动的断言(节选),防止顺手放宽。
HARDEN_KEEP = [
    'Assert.Contains("catch { $disableError = @($_) }", script);',
    'Assert.Contains("if ($disableError)", script);',
    'Assert.Contains("if ($null -ne $state.disabledRules)", script);',
    'Assert.Contains("foreach ($name in @($state.disabledRules))", script);',
    'Assert.Contains("Enable-NetFirewallRule -ErrorAction SilentlyContinue", script);',
    'Assert.Contains("catch { $enableError = @($_) }", script);',
    'Before(script, "Set-NetFirewallProfile -Profile $p.Name", "Remove-Item -LiteralPath $statePath");',
    'Assert.Contains("-Profile Domain,Private,Public -DefaultOutboundAction Allow", script);',
    'Assert.Equal(new[] { "RemoveRulesByPrefix", "RestoreProfileDefault" }, plan.Select(action => action.GetType().Name));',
]
HARDEN_NEW = [
    'Assert.DoesNotContain("foreach ($rule in $foreignRules)", script);',
    'Assert.Contains("' + BATCH_DISABLE + '", script);',
    'Assert.DoesNotContain("-PolicyStore PersistentStore -Name $name", script);',
    'Assert.Contains("$targets | Enable-NetFirewallRule", script);',
    'Before(script, "Set-NetFirewallProfile -Profile $p.Name", "Enable-NetFirewallRule");',
    'Before(script, "Enable-NetFirewallRule", "Remove-Item -LiteralPath $statePath");',
]


def text(path):
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def fail(problems):
    for item in problems:
        print("未通过:", item)
    sys.exit(1 if problems else 0)


def need(body, words, name, bad):
    for word in words:
        if word not in body:
            bad.append(f"{name} 缺 {word}")


def between(body, start, end):
    head, found, rest = body.partition(start)
    if not found:
        return ""
    return rest.partition(end)[0]


def shape():
    bad = []
    planner = text(PLANNER)
    if SLOW_LOOKUP in planner:
        bad.append("KillSwitchPlanner.cs 仍有按名字逐条查询:" + SLOW_LOOKUP)
    if planner.count("foreach ($rule in $foreignRules)") != 1:
        bad.append("逐条停用的循环应只剩巡检里那一处")
    restore = between(planner, "case RestoreProfileDefault:", "case RecoverFallback:")
    need(restore, [BATCH_ENABLE, LOOKUP, "$restoreFailed", "防火墙恢复记录不完整，需人工处理。",
                   "防火墙恢复记录无效。", "部分防火墙规则恢复失败，恢复记录已保留，请联系管理员。",
                   "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow"],
         "撤销脚本", bad)
    profile = restore.find("Set-NetFirewallProfile -Profile $p.Name")
    enable = restore.find("Enable-NetFirewallRule")
    delete = restore.find("Remove-Item -LiteralPath $statePath")
    if not (0 <= profile < enable < delete):
        bad.append("撤销脚本的次序应是:改回默认出站 → 批量启用规则 → 删恢复记录")
    fallback = between(planner, "case RecoverFallback:", "case VerifyProfiles:")
    need(fallback, [BATCH_ENABLE, LOOKUP, "$_.Direction -eq 'Outbound'", "killswitch-recovery.json", "exit 0"],
         "降级恢复脚本", bad)
    disable = between(planner, "case DisableForeignAllowRules:", "case AddRule rule:")
    need(disable, [BATCH_DISABLE, "$state.unmanagedRules = @(Read-UnmanagedRules)"], "套用脚本", bad)
    if disable.count("Write-State $state") < 2:
        bad.append("套用脚本停用规则前后都要落恢复记录")
    need(planner, ["case Patrol patrol:", "$rule | Disable-NetFirewallRule"], "巡检脚本(不该动)", bad)
    need(text(RUNNER), ['string Error = ""', "CreateNoWindow = true", "UseShellExecute = false"], "CommandRunner.cs", bad)
    applier = text(APPLIER)
    need(applier, [
        "Action<string>? log = null",
        "internal TimeSpan ScriptTimeout { get; init; } = TimeSpan.FromSeconds(180);",
        'public const string ScriptTimedOut = "系统防火墙设置超过时限没有完成，已中止。";',
        "new TimeoutException(ScriptTimedOut)",
        "public static string SanitizeError(string? text)",
        "防火墙脚本[", "] 退出码 ", "，用时 ", " 毫秒", "，错误摘要：", "] 超时，用时 ",
        "过滤层安装：", "过滤层移除：", "[地址]", "[用户]", "timeout",
        "CreateNoWindow = true",
        # 既有的三句异常文字不许动。
        "防火墙操作失败，恢复记录已保留，请联系管理员。",
        "断网保护巡检失败,请联系管理员。",
        "启动时未能按原记录完整恢复断网保护，已降级恢复网络设置并归档记录；请联系管理员检查恢复记录。",
    ], "KillSwitchApplier.cs", bad)
    for phase in PHASES:
        if '"' + phase + '"' not in applier:
            bad.append("KillSwitchApplier.cs 缺阶段名 " + phase)
    if "FromSeconds(180)" in applier.replace("ScriptTimeout { get; init; } = TimeSpan.FromSeconds(180)", ""):
        bad.append("KillSwitchApplier.cs 里写死的 180 秒应都改用 ScriptTimeout")
    fail(bad)


def tests():
    bad = []
    fast = text(FAST)
    if not fast:
        bad.append("缺文件 WinClient.Tests/KillSwitchRestoreFastTests.cs")
    for method in NEW_TESTS:
        if " " + method + "(" not in fast:
            bad.append("KillSwitchRestoreFastTests 缺用例 " + method)
    for word in ("WfpEngine.CreateProduction", "new RouteGuard(", "runas", "Invoke-Expression"):
        if word in fast:
            bad.append("KillSwitchRestoreFastTests 不许碰真系统:" + word)
    if "ParseFile" not in fast:
        bad.append("语法解析用例要用 Parser.ParseFile,只解析不执行")
    if "CreateNoWindow = true" not in fast:
        bad.append("测试里启动的子进程要隐藏窗口")
    harden = text(HARDEN)
    for method in HARDEN_TESTS:
        if " " + method + "(" not in harden:
            bad.append("KillSwitchHardenTests 用例缺失或名字不对:" + method)
    if harden.count("[Fact]") != 7 or "[Theory]" in harden:
        bad.append("KillSwitchHardenTests 应仍是 7 个用例")
    need(harden, HARDEN_KEEP, "KillSwitchHardenTests(不许动的断言)", bad)
    need(harden, HARDEN_NEW, "KillSwitchHardenTests(按契约改的断言)", bad)
    fail(bad)


def scope():
    def git(*args):
        out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
        return [line.strip() for line in out.decode("utf-8").split("\n") if line.strip()]

    base = git("merge-base", "origin/main", "HEAD")[0]
    changed = set(git("diff", "--name-only", base))
    changed |= set(git("ls-files", "--others", "--exclude-standard"))
    fail(sorted("改了允许清单以外的文件:" + path for path in changed if path not in ALLOWED))


if __name__ == "__main__":
    commands = {"shape": shape, "tests": tests, "scope": scope}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print("用法:python 本文件 shape|tests|scope")
        sys.exit(2)
    commands[sys.argv[1]]()
