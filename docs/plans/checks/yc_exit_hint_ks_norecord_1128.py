"""出口提示提速与无记录撤销单 yc-exit-hint-ks-norecord-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
CONTROLLER = WIN / "WinClient.Core/Client/ClientController.cs"
PLANNER = WIN / "WinClient.Core/Firewall/KillSwitchPlanner.cs"
APPLIER = WIN / "WinClient.Core/Firewall/KillSwitchApplier.cs"
DISABLED = WIN / "WinClient.Core/Firewall/DisabledKillSwitch.cs"
INSTALLER = WIN / "WinClient.App/Hosting/InstallerRunner.cs"
CONTROLLER_TESTS = WIN / "WinClient.Tests/ControllerTests.cs"
FIREWALL_TESTS = WIN / "WinClient.Tests/FirewallTests.cs"
HARDEN_TESTS = WIN / "WinClient.Tests/KillSwitchHardenTests.cs"
NEW_TESTS_FILE = WIN / "WinClient.Tests/KillSwitchNoRecordTests.cs"
ARCH_DOC = ROOT / "docs/winclient/架构说明.md"
KS_DOC = ROOT / "docs/winclient/断网保护加固说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Client/ClientController.cs",
    "winclient/WinClient.Core/Firewall/KillSwitchPlanner.cs",
    "winclient/WinClient.Core/Firewall/KillSwitchApplier.cs",
    "winclient/WinClient.Core/Firewall/DisabledKillSwitch.cs",
    "winclient/WinClient.App/Hosting/InstallerRunner.cs",
    "winclient/WinClient.Tests/ControllerTests.cs",
    "winclient/WinClient.Tests/FirewallTests.cs",
    "winclient/WinClient.Tests/KillSwitchHardenTests.cs",
    "winclient/WinClient.Tests/KillSwitchNoRecordTests.cs",
    "docs/winclient/架构说明.md",
    "docs/winclient/断网保护加固说明.md",
}
PAIRING_HINT = "连不到澳洲出口，现在可能上不了网。可以点「断开」恢复原来的网络；小主机换过地址的话，在小主机上重新导出配对文件再导入。"
AUTH_HINT = "连不到澳洲出口，现在可能上不了网。可以点「断开」恢复原来的网络，或联系管理员。"
NO_RECORD_WARNING = "断网保护的恢复记录不见了，系统防火墙的默认出站已按 Windows 默认改回「允许」；原来设成「阻止」的，请到 Windows 安全中心改回。"
JOURNAL_LINE = "撤销断网保护：没有恢复记录，默认出站已按 Windows 默认改回允许"
STUBS = ["Get-NetFirewallRule", "Remove-NetFirewallRule", "Enable-NetFirewallRule", "Get-NetFirewallProfile", "Set-NetFirewallProfile"]
OLD_UNCONDITIONAL = "} else { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow }"
EVIDENCE = "$hadGlobalRules = @(Get-NetFirewallRule -Name 'YuanC-KS-*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'YuanC-KS-App-*' }).Count -gt 0"
NEW_CONTROLLER_TESTS = [
    "UnverifiableExitShowsHintAfterFirstRoundWithoutDisconnecting",
    "UnverifiableExitRechecksEveryMinuteUntilVerified",
    "DisconnectWithoutRecordShowsWindowsDefaultWarning",
    "DisconnectWithRecordKeepsRestoredMessage",
    "AbandonWithoutRecordAppendsWindowsDefaultWarning",
]
NEW_RECORD_TESTS = [
    "RemoveScriptReadsEvidenceBeforeDeletingRules",
    "NoRecordBranchOnlyTouchesBlockedProfilesWithGlobalEvidence",
    "NoRecordScriptParsesInWindowsPowerShell",
    "ApplierSetsWarningAndRecoveryLineOnWindowsDefault",
    "ApplierClearsWarningWhenUntouchedOrRecordPresent",
    "DisabledKillSwitchForwardsRemoveWarning",
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


def before(body, first, second, name, bad):
    a = body.find(first)
    b = body.find(second)
    if a < 0 or b < 0 or a > b:
        bad.append(f"{name}:{first} 要出现在 {second} 之前")


def between(body, start, end):
    head, found, rest = body.partition(start)
    if not found:
        return ""
    return rest.partition(end)[0]


def shape():
    bad = []
    controller = text(CONTROLLER)
    need(controller, ["internal const int UnverifiableHintRounds = 1;",
                      "internal static readonly TimeSpan UnverifiableRecheckInterval = TimeSpan.FromMinutes(1);",
                      "internal const string PairingUnverifiableHint = \"" + PAIRING_HINT + "\";",
                      "internal const string AuthUnverifiableHint = \"" + AUTH_HINT + "\";",
                      "LastRemoveWarning", "\"已断开。\"", JOURNAL_LINE], "ClientController.cs", bad)
    if controller.count("UnverifiableRecheckInterval") < 2:
        bad.append("ClientController.cs 的复核间隔没有用上 UnverifiableRecheckInterval")
    if "出口已连续" in controller:
        bad.append("ClientController.cs 还留着旧的「出口已连续 N 轮」提示")
    disconnect = between(controller, "public async Task DisconnectAsync()", "public async Task RefreshSessionAsync()")
    need(disconnect, ["已断开，原网络设置已恢复。"], "DisconnectAsync(有记录时原句不变)", bad)
    planner = text(PLANNER)
    if OLD_UNCONDITIONAL in planner:
        bad.append("KillSwitchPlanner.cs 还留着无记录时无条件改回允许的写法")
    need(planner, [EVIDENCE, "YUANC-NO-RECORD=windows_default", "YUANC-NO-RECORD=untouched",
                   "[string]$_.DefaultOutboundAction -eq 'Block'", "-DefaultOutboundAction Allow"], "KillSwitchPlanner.cs", bad)
    restore = between(planner, "case RestoreProfileDefault:", "case RecoverFallback:")
    if "$hadGlobalRules" not in restore:
        bad.append("撤销脚本的无记录分支要按 $hadGlobalRules 判断")
    fallback = between(planner, "case RecoverFallback:", "case VerifyProfiles:")
    need(fallback, ["Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow",
                    "$profilesApplied = 'windows_default'"], "降级恢复脚本(不该动)", bad)
    applier = text(APPLIER)
    need(applier, ["string? LastRemoveWarning => null;", "public string? LastRemoveWarning { get; private set; }",
                   "public const string NoRecordRemoveWarning = \"" + NO_RECORD_WARNING + "\";",
                   "YUANC-NO-RECORD=windows_default", "remove no_record windows_default", "killswitch-recovery.log"],
         "KillSwitchApplier.cs", bad)
    need(text(DISABLED), ["LastRemoveWarning", "inner.LastRemoveWarning"], "DisabledKillSwitch.cs", bad)
    need(text(INSTALLER), ["LastRemoveWarning"], "InstallerRunner.cs", bad)
    fail(bad)


def tests():
    bad = []
    ct = text(CONTROLLER_TESTS)
    for method in NEW_CONTROLLER_TESTS:
        if " " + method + "(" not in ct:
            bad.append("ControllerTests 缺用例 " + method)
    for old in ("UnverifiableExitShowsHintAfterThreeRoundsWithoutDisconnecting",):
        if " " + old + "(" in ct:
            bad.append("ControllerTests 旧用例应按契约改名:" + old)
    if " UnverifiableCounterResetsWhenExitRecovers(" not in ct:
        bad.append("ControllerTests 用例 UnverifiableCounterResetsWhenExitRecovers 不许删")
    nt = text(NEW_TESTS_FILE)
    if not nt:
        bad.append("缺文件 WinClient.Tests/KillSwitchNoRecordTests.cs")
    for method in NEW_RECORD_TESTS:
        if " " + method + "(" not in nt:
            bad.append("KillSwitchNoRecordTests 缺用例 " + method)
    for word in ("WfpEngine.CreateProduction", "new RouteGuard(", "new CommandRunner(", "runas", "Invoke-Expression"):
        if word in nt:
            bad.append("KillSwitchNoRecordTests 不许碰真系统:" + word)
    need(nt, ["ParseFile"], "KillSwitchNoRecordTests(语法解析只解析不执行)", bad)
    need(nt, ["KillSwitchApplier.CreateStartInfo("] + ["function " + name for name in STUBS],
         "KillSwitchNoRecordTests(真跑脚本时防火墙命令全部换成桩函数)", bad)
    for path, name in ((FIREWALL_TESTS, "FirewallTests"), (HARDEN_TESTS, "KillSwitchHardenTests")):
        body = text(path)
        if 'Assert.Contains("-Profile Domain,Private,Public -DefaultOutboundAction Allow", script);' in body:
            bad.append(name + " 还在断言无记录时无条件改回允许")
        need(body, ['Assert.Contains("YUANC-NO-RECORD=windows_default", script);'], name, bad)
    harden = text(HARDEN_TESTS)
    if harden.count("[Fact]") != 7 or "[Theory]" in harden:
        bad.append("KillSwitchHardenTests 应仍是 7 个用例")
    fail(bad)


def docs():
    bad = []
    arch = text(ARCH_DOC)
    if "连续 3 轮无法核验" in arch:
        bad.append("架构说明.md 还写着连续 3 轮才提示")
    need(arch, [PAIRING_HINT, AUTH_HINT, "1 分钟"], "架构说明.md", bad)
    ks = text(KS_DOC)
    section = between(ks, "### 没有恢复记录时点断开", "\n## ")
    if not section:
        bad.append("断网保护加固说明.md 缺「### 没有恢复记录时点断开」一节")
    need(section, [NO_RECORD_WARNING, "YuanC-KS-App-", "untouched", "windows_default", "卸载", "真机"],
         "「没有恢复记录时点断开」一节", bad)
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
    commands = {"shape": shape, "tests": tests, "docs": docs, "scope": scope}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print("用法:python 本文件 shape|tests|docs|scope")
        sys.exit(2)
    commands[sys.argv[1]]()
