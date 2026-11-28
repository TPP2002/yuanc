"""工单 yc-auth-permit-refresh-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PLANNER = "winclient/WinClient.Core/Firewall/KillSwitchPlanner.cs"
APPLIER = "winclient/WinClient.Core/Firewall/KillSwitchApplier.cs"
RECORD = "winclient/WinClient.Core/Firewall/KillSwitchRecord.cs"
CONTROLLER = "winclient/WinClient.Core/Client/ClientController.cs"
APPLIER_TESTS = "winclient/WinClient.Tests/AuthPermitRefreshTests.cs"
CONTROLLER_TESTS = "winclient/WinClient.Tests/ControllerAuthPermitTests.cs"
ALLOWED = {PLANNER, APPLIER, RECORD, CONTROLLER, APPLIER_TESTS, CONTROLLER_TESTS}

REFRESH = "public async Task<bool> RefreshAuthAsync(AuthEndpoint auth)"
PERMIT = "private async Task RefreshAuthPermitAsync()"
INITIALIZE = "public async Task InitializeAsync(bool autoConnect = true, bool keepProtection = false)"
KEPT_LINE = 'WriteJournal("启动：接回断网保护，随后自动连接");'
# 这两个文件改动前的每一行都要按原顺序原样留着(只许加行)。
ADD_ONLY = (APPLIER, CONTROLLER)
# 文件里必须有的片段(一字不差)。
NEEDED = {
    PLANNER: ["public static IReadOnlyList<FirewallAction> RefreshAuth(AuthEndpoint auth)",
              "private static AddRule AuthRule(AuthEndpoint auth)", "actions.Add(AuthRule(auth));"],
    APPLIER: ["Task<bool> RefreshAuthAsync(AuthEndpoint auth) => Task.FromResult(false);", REFRESH,
              'public const string WfpAuthRefreshFailed = "系统过滤层里登录服务器的放行没能换成当前程序。";'],
    RECORD: ["internal sealed record KillSwitchRecord(", "public static KillSwitchRecord? Read(string path)",
             "public bool Has(AddRule rule)", "public RecordedNode? Node()", '"value"',
             "internal sealed record RecordedRule(", "internal sealed record RecordedNode("],
    CONTROLLER: [PERMIT, "await RefreshAuthPermitAsync();", '"启动：登录服务器的放行已换成当前程序"',
                 '"启动：登录服务器的放行不用换"', '"启动：登录服务器的放行没换成："'],
}
# 方法正文里必须有的、不许有的。
MEMBERS = {
    APPLIER: {REFRESH: (
        ["KillSwitchPlanner.RefreshAuth(auth)", "gate.WaitAsync()", "gate.Release()", "KillSwitchRecord.Read(StatePath)",
         '"global"', "wfpOffPath", "wfp.ListFilterNames()", "WfpPlanner.PlanGlobal(", "wfp.Install(policy)",
         "wfpPolicy = policy", 'RunActionsAsync(actions, "换登录放行")', "WfpAuthRefreshFailed"],
        ["wfp.Remove", "RemoveWfp", "RecoverFirewallAsync", "RestoreProfileDefault", "SetProfileDefault", "RemoveRulesByPrefix"])},
    CONTROLLER: {
        PERMIT: (["sessionSource is not AuthServerSessionSource", "authEndpoint is null", "firewall.RefreshAuthAsync(authEndpoint)",
                  "IsOperational(ex)", "ConnectJournal.Describe(ex)"],
                 ["FailAsync", "message =", "protection =", "machine.Handle", "Publish("]),
        INITIALIZE: (["await RefreshAuthPermitAsync();"], []),
    },
    PLANNER: {"public static IReadOnlyList<FirewallAction> Plan(": (["actions.Add(AuthRule(auth));"], ["鉴权服务器", "后台服务程序必须"])},
}
# 这些方法从签名到正文结束一个字不能变(和改动前逐字比)。
UNTOUCHED = {
    PLANNER: ["public static string ToPowerShellScript(", "public static IReadOnlyList<FirewallAction> PlanApps(",
              "private static IEnumerable<FirewallAction> NodeRules("],
    APPLIER: ["private async Task<string> ExecuteAsync(", "private async Task<string> RunActionsAsync(",
              "public async Task<string?> RecoverAsync()", "private bool InstallWfp(", "private bool RemoveWfp()"],
    CONTROLLER: ["internal async Task ConnectAsync(bool fromUser)", "private async Task FetchSessionAsync()",
                 "private async Task ExecuteEffectsAsync(Transition transition)", "private async Task PatrolAsync(object cycle)"],
}
# 整个文件里不许出现的片段。
BANNED = {RECORD: ["File.Write", "File.Delete", "File.Move", "File.Copy", "ProcessStartInfo"]}
# 这三句报错在 KillSwitchPlanner.cs 里各只许出现一次(校验不许抄两份)。
ONCE = ["鉴权服务器必须是 IPv4 数字地址。", "鉴权服务器端口必须在 1 到 65535 之间。", "后台服务程序必须是绝对路径。"]
NEW_TESTS = {
    APPLIER_TESTS: {
        "RefreshAuthPlanIsTheAuthRuleFromFullPlan": ["KillSwitchPlanner.RefreshAuth(", "KillSwitchPlanner.Plan(", '"YuanC-KS-Auth"',
                                                     "Assert.Single(", "JsonSerializer.Serialize("],
        "RefreshAuthScriptRewritesOnlyAuthRuleAndRecord": [
            "KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.RefreshAuth(", "\"New-NetFirewallRule -Name 'YuanC-KS-Auth'\"",
            "\"$_.Name -ne 'YuanC-KS-Auth'\"", '"if ($null -ne $state) { Write-State $state }"',
            'DoesNotContain("Set-NetFirewallProfile"', 'DoesNotContain("YuanC-KS-Node"'],
        "RefreshAuthRejectsBadEndpointBeforeTouchingSystem": ["ThrowsAsync<ArgumentException>(", "RefreshAuthAsync(", "Assert.Empty("],
        "ChangedProgramRewritesFirewallRuleAndReinstallsFilters": [
            "Assert.True(await", "RefreshAuthAsync(", 'new[] { "list", "install", "script" }',
            "KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.RefreshAuth(", '"YuanC-WFP-Auth"', '"YuanC-WFP-Node-Tcp"',
            '"YuanC-WFP-Node-Udp"', '"192.0.2.5/32"', "24443", "AppPath"],
        "SameProgramDoesNothing": ["Assert.False(await", "RefreshAuthAsync(", "Assert.Empty(", "ToUpperInvariant()"],
        "NoRecordAppsModeOrBrokenRecordDoesNothing": ['[InlineData("missing")]', '[InlineData("apps")]', '[InlineData("broken")]',
                                                      "Assert.False(await", "Assert.Empty("],
        "RecordWithoutNodeRulesOnlyRewritesFirewallRule": ["Assert.True(await", 'new[] { "script" }'],
        "EmptyFilterLayerIsNotReinstalled": ["Assert.True(await", 'new[] { "list", "script" }'],
        "OffSwitchSkipsFilterLayer": ['"wfp-off"', "Assert.True(await", 'new[] { "script" }'],
        "FilterFailureStillRewritesFirewallRuleThenReports": ["ThrowsAsync<WfpUnavailableException>(", "KillSwitchApplier.WfpAuthRefreshFailed",
                                                              'new[] { "list", "install", "script" }'],
        "ScriptFailureKeepsOriginalError": ["ThrowsAsync<InvalidOperationException>(", '"防火墙操作失败，恢复记录已保留，请联系管理员。"'],
        "RecordReaderAcceptsPowerShellArrayShapes": ["KillSwitchRecord.Read(", "new UTF8Encoding(true)", "value", "Count", ".Node()",
                                                     '"global"', "Assert.NotNull("],
        "PatrolAfterRefreshComparesAgainstReinstalledFilters": ["RefreshAuthAsync(", "PatrolAsync(", 'new[] { "list", "script" }',
                                                                'new[] { "list", "install", "script" }'],
    },
    CONTROLLER_TESTS: {
        "KeptStartRefreshesAuthPermitBeforeFetchingSession": [
            "keepProtection: true", 'new[] { "refresh-auth", "session", "apply", "start" }', "ConnectionState.Connected",
            '"启动：登录服务器的放行已换成当前程序"', "Assert.Single("],
        "KeptStartWithoutRefreshCannotFetchSession": [
            "keepProtection: true", "RefreshError", 'DoesNotContain("apply"', "Assert.NotEqual(ConnectionState.Connected",
            "ProtectionActive", '"启动：登录服务器的放行没换成："', '"session"'],
        "SameProgramJournalsNoChange": ["keepProtection: true", '"启动：登录服务器的放行不用换"', "ConnectionState.Connected"],
        "PairingModeOrMissingEndpointDoesNotRefresh": ["[InlineData(true)]", "[InlineData(false)]", "PairingSessionSource",
                                                       'DoesNotContain("refresh-auth"', "ConnectionState.Connected"],
        "StartWithoutKeptProtectionDoesNotRefresh": ["[InlineData(false, true)]", "[InlineData(true, false)]",
                                                     'DoesNotContain("refresh-auth"', "Assert.Empty("],
        "MissingCredentialsParksWithoutRefresh": ["keepProtection: true", 'DoesNotContain("refresh-auth"',
                                                  "ConnectionState.NeedsManual", "ProtectionActive"],
    },
}
SKIPS = r"\bSkip\s*=|\bAssert\.Skip\w*\s*\(|\bSkip\.If\w*\s*\(|\bSkippable(?:Fact|Theory)\b"
REAL_WAITS = r"\bTask\.Delay\s*\(|\bThread\.Sleep\s*\("


def text(path):
    file = ROOT / path
    return file.read_text(encoding="utf-8").replace("\r\n", "\n") if file.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT, stderr=subprocess.DEVNULL)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    try:
        return git("show", f"{base()}:{path}").replace("\r\n", "\n")
    except subprocess.CalledProcessError:
        return ""


def member(source, signature):
    """取一个方法从签名到正文花括号结束的全文;找不到返回空串。"""
    start = source.find(signature)
    brace = source.find("{", start) if start >= 0 else -1
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    return ""


def dropped(new, old):
    """改动前的每一行都要按原顺序留在新文件里;返回第一处被改或被删的行。"""
    rows = iter(new.splitlines())
    for line in old.splitlines():
        if not any(row == line for row in rows):
            return line.strip()[:70] or "(空行)"
    return None


def shape_problems(new, old):
    """new、old:路径 → 全文。old 里新文件为空串。"""
    bad = []
    for path in ADD_ONLY:
        if not old[path]:
            bad.append(f"检查脚本读不到改动前的 {path},请交 blocked 告诉派单方")
            continue
        line = dropped(new[path], old[path])
        if line is not None:
            bad.append(f"{path} 只许加行,这一行被改了或删了:{line}")
    for path, tokens in NEEDED.items():
        if not new[path]:
            bad.append(f"缺文件 {path}")
            continue
        bad += [f"{path} 缺这一段或写法与契约不一致:{token[:80]}" for token in tokens if token not in new[path]]
    for path, members in MEMBERS.items():
        for signature, (needed, forbidden) in members.items():
            body = member(new[path], signature)
            if not body:
                bad.append(f"{path} 缺 {signature}")
                continue
            bad += [f"{signature} 里没有契约要求的 {token}" for token in needed if token not in body]
            bad += [f"{signature} 里不许出现 {token}" for token in forbidden if token in body]
    for path, signatures in UNTOUCHED.items():
        for signature in signatures:
            was, now = member(old[path], signature), member(new[path], signature)
            if not was:
                bad.append(f"检查脚本在改动前的 {path} 里找不到 {signature},请交 blocked 告诉派单方")
            elif was != now:
                bad.append(f"不许动的方法被改了:{signature}")
    for path, tokens in BANNED.items():
        bad += [f"{path} 里不许出现 {token}" for token in tokens if token in new[path]]
    bad += [f"KillSwitchPlanner.cs 里「{token}」要正好出现一次(校验收进 AuthRule,不抄两份)"
            for token in ONCE if new[PLANNER].count(token) != 1]

    start = member(new[CONTROLLER], INITIALIZE)
    spots = [start.find(KEPT_LINE), start.find("await RefreshAuthPermitAsync();"), start.find("else if (keptMissing)")]
    if min(spots) < 0 or spots != sorted(spots):
        bad.append("InitializeAsync 里 await RefreshAuthPermitAsync(); 要放在「启动：接回断网保护，随后自动连接」那行之后、else if (keptMissing) 之前")
    if new[CONTROLLER].count("RefreshAuthPermitAsync(") != 2:
        bad.append("ClientController.cs 里 RefreshAuthPermitAsync( 要正好出现两次(定义一次,保持保护启动时调一次)")
    if new[CONTROLLER].count("firewall.RefreshAuthAsync(") != 1:
        bad.append("ClientController.cs 里 firewall.RefreshAuthAsync( 要正好出现一次")
    refresh = member(new[APPLIER], REFRESH)
    order = [refresh.find(mark) for mark in ("wfp.Install(policy)", 'RunActionsAsync(actions, "换登录放行")', "new WfpUnavailableException(WfpAuthRefreshFailed)")]
    if refresh and (min(order) < 0 or order != sorted(order)):
        bad.append("RefreshAuthAsync 里先重装过滤层,再跑防火墙脚本,脚本跑完才报过滤层没换成")
    return bad


def tests_problems(new):
    bad = []
    for path, cases in NEW_TESTS.items():
        source = new[path]
        if not source:
            bad.append(f"缺测试文件 {path}")
            continue
        for name, tokens in cases.items():
            head = re.search(rf"\[(?:Fact|Theory)\]((?:\s*\n\s*\[InlineData\([^\n]*\)\])*)\s*\n\s*public (?:async Task|void) {name}\(", source)
            body = member(source, f" {name}(")
            if not head or not body:
                bad.append(f"{path} 缺用例 {name}(要带 [Fact] 或 [Theory])")
                continue
            whole = head.group(1) + body
            bad += [f"用例 {name} 里没有契约要求的 {token}" for token in tokens if token not in whole]
            if body.count("Assert.") < 2:
                bad.append(f"用例 {name} 的断言太少")
        if re.search(SKIPS, source):
            bad.append(f"{path} 里不许跳过")
        if re.search(REAL_WAITS, source):
            bad.append(f"{path} 里不许真的等时间(Task.Delay / Thread.Sleep)")
    return bad


def shape():
    paths = sorted(ALLOWED - set(NEW_TESTS))
    return shape_problems({path: text(path) for path in paths}, {path: before(path) for path in paths})


def tests():
    return tests_problems({path: text(path) for path in NEW_TESTS})


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
