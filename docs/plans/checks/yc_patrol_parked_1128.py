"""工单 yc-patrol-parked-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTROLLER = "winclient/WinClient.Core/Client/ClientController.cs"
TESTS = "winclient/WinClient.Tests/ControllerTests.cs"
ALLOWED = {CONTROLLER, TESTS}

# 这些方法的正文一个字不能变(和改动前逐字比)。
UNTOUCHED = [
    'private void Schedule(TimeSpan delay, Func<Task> action, string purpose = "")',
    "private async Task RunScheduledAsync(",
    "private async Task FailAsync(",
    "private async Task AbandonAsync(",
    "private async Task MaybeAbandonAfterLoginFailureAsync()",
    "internal async Task ConnectAsync(bool fromUser)",
    "public async Task RefreshSessionAsync()",
    "public async Task ChangeSessionSourceAsync(",
    "private async Task ExecuteAsync(Transition transition)",
    "private async Task ExecuteEffectsAsync(Transition transition)",
    "private async Task FetchSessionAsync()",
    "private async Task ApplySessionAsync(",
    "private async Task RenewAsync(",
    "private async Task CheckExitAsync(",
    "private async Task CheckEnvironmentAsync(",
    "private async Task<string?> PatrolNewExecutablesAsync()",
    "private void JournalPatrol()",
]
# 这些方法只许加行:原有的行一行不少、次序不变;第二项是最多加几行(不算注释和空行)。
ONLY_ADDED = {
    "public async Task InitializeAsync(": 9,
    "public async Task DisconnectAsync()": 1,
    "private async Task<(UndoState State, string? Warning)> RemoveProtectionAsync()": 1,
    "public void Dispose()": 1,
}
LINES = [
    'internal const string PatrolModeMismatchStatus = "代理范围与断网保护记录不一致，本轮没有检查防火墙规则";',
    "private CancellationTokenSource patrolLifetime = new();",
    "private bool ShouldPatrol => protection;",
    "private bool PatrolMaySpeak => machine.State is ConnectionState.Connected or ConnectionState.Reconnecting;",
    'private bool PatrolModeMismatch => firewall.HasPendingState && (firewall.PendingMode ?? "global") != ModeName(activeRouting);',
    "internal static readonly TimeSpan PatrolInterval = TimeSpan.FromSeconds(60);",
]
SYNC_PATROL = """
    private void SyncPatrol()
    {
        if (patrolLifetime.IsCancellationRequested || (!ShouldPatrol && patrolScheduled))
        {
            patrolLifetime.Cancel();
            patrolLifetime = new();
            patrolScheduled = false;
            patrolCycle = null;
        }
        if (ShouldPatrol && !patrolScheduled && !disposed)
        {
            patrolCycle = new object();
            SchedulePatrol(patrolCycle);
        }
    }
"""
SCHEDULE_PATROL = """
    private void SchedulePatrol(object cycle)
    {
        patrolScheduled = true;
        _ = RunPatrolAsync(cycle, patrolLifetime.Token);
    }
"""
RUN_PATROL = """
    private async Task RunPatrolAsync(object cycle, CancellationToken token)
    {
        try
        {
            await DelayForPurposeAsync(PatrolInterval, token, "巡检");
            await gate.WaitAsync(token);
            try { if (!disposed) await PatrolAsync(cycle); }
            finally { Publish(); gate.Release(); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
"""
ROUTING_LOAD = [
    "activeRouting = routingSettings?.Read() ?? RoutingPolicy.Global;",
    "activeScopes = activeRouting.Mode == RoutingMode.Apps ? activeRouting.Apps.Select(scopeResolver).ToArray() : [];",
    'catch (Exception ex) when (IsOperational(ex)) { WriteJournal("启动：读不到代理范围设置：" + ConnectJournal.Describe(ex)); }',
]
NEW_TESTS = {
    "PatrolContinuesWhileParkedWithProtection": ["FireParkedPatrol(", '"正常"', "AuthResult.InvalidToken"],
    "PatrolRearmsAfterFailedDisconnect": ["FireParkedPatrol(", '"已重建 1 条本项目规则"', "tunnel.FailStop = true"],
    "ParkedPatrolWarningStaysOutOfMessage": ["FireParkedPatrol(", "FirewallIneffectiveException", '"防火墙"'],
    "StartupParkedWithoutSourceStillPatrols": ["FireParkedPatrol(", "KeptWithoutPairingMessage", '"巡检失败,下一轮重试"'],
    "StartupParkedAppsModePatrolsAppRules": ["FireParkedPatrol(", "AppRuleNames(1)", '"已为新出现的 1 个程序文件补上保护"',
                                             'PendingMode = "apps"'],
    "ParkedPatrolSkipsFirewallWhenRecordModeDiffers": ["FireParkedPatrol(", "PatrolModeMismatchStatus", 'PendingMode = "apps"'],
    "PatrolStopsOnceProtectionRemoved": ["Advance(TimeSpan.FromMinutes(10))", "RefreshSessionAsync()"],
    "AbandonedFirstAttemptLeavesPatrolReadyForNextConnect": ["FirstStartMissingTunnel(", "FireAndPublish("],
}


def text(path):
    file = ROOT / path
    return file.read_text(encoding="utf-8").replace("\r\n", "\n") if file.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    return git("show", f"{base()}:{path}").replace("\r\n", "\n")


def member(source, signature):
    """取一个方法从签名到配对右花括号的全文;找不到返回空串。"""
    start = source.find(signature)
    if start < 0:
        return ""
    depth = 0
    for index in range(source.index("{", start), len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    return ""


def squash(source):
    """去掉行尾注释、整行注释和全部空白,只比代码本身。"""
    return re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", source))


def code_lines(source):
    return [line.strip() for line in source.splitlines() if line.strip() and not line.strip().startswith("//")]


def same(actual, expected, label, bad):
    if not actual:
        bad.append(f"找不到 {label}")
    elif squash(actual) != squash(expected):
        bad.append(f"{label} 和契约写的不一致(只许照 goal 改,别的一个字不动)")


def shape_problems(new, old):
    bad = []
    for line in LINES:
        if line not in new:
            bad.append(f"ClientController.cs 缺这一行或文字与契约不一致:{line[:60]}")
    if "ConnectionState.Connected or ConnectionState.Reconnecting;" in member(new, "private void UpdateMonitoring()") or \
            "private bool ShouldPatrol => protection && " in new:
        bad.append("ShouldPatrol 还带着连接状态的条件")
    for word, why in (("Schedule(PatrolInterval", "巡检定时不许再走 Schedule"),
                      ("patrolLifetime.Dispose", "旧的巡检取消源只取消、不释放")):
        if word in new:
            bad.append(f"ClientController.cs 里出现了 {word}:{why}")

    for signature in UNTOUCHED:
        was, now = member(old, signature), member(new, signature)
        if not was:
            bad.append(f"检查脚本在改动前的代码里找不到 {signature},请交 blocked 告诉派单方")
        elif was != now:
            bad.append(f"不许动的方法被改了:{signature}")

    for signature, limit in ONLY_ADDED.items():
        was, now = code_lines(member(old, signature)), code_lines(member(new, signature))
        rest = iter(now)
        if not now or not all(line in rest for line in was):
            bad.append(f"{signature} 原有的行被删改了(这个方法只许加行)")
        elif not 1 <= len(now) - len(was) <= limit:
            bad.append(f"{signature} 加的行数不对:加了 {len(now) - len(was)} 行,契约是 1 到 {limit} 行")

    same(member(new, "private void SyncPatrol()"), SYNC_PATROL, "SyncPatrol", bad)
    same(member(new, "private void SchedulePatrol(object cycle)"), SCHEDULE_PATROL, "SchedulePatrol", bad)
    same(member(new, "private async Task RunPatrolAsync(object cycle, CancellationToken token)"), RUN_PATROL, "RunPatrolAsync", bad)

    monitoring = member(old, "private void UpdateMonitoring()")
    cut = monitoring.find("if (!ShouldPatrol)")
    same(member(new, "private void UpdateMonitoring()"), monitoring[:cut] + "SyncPatrol();\n    }", "UpdateMonitoring", bad)

    patrol = member(old, "private async Task PatrolAsync(object cycle)") \
        .replace("if (!ReferenceEquals(cycle, patrolCycle) || !ShouldPatrol) return;",
                 "if (!ReferenceEquals(cycle, patrolCycle)) return;\nif (!ShouldPatrol) { SyncPatrol(); return; }") \
        .replace("var addedNote = await PatrolNewExecutablesAsync();",
                 "if (PatrolModeMismatch) { guardStatus = PatrolModeMismatchStatus; return; }\n"
                 "var addedNote = await PatrolNewExecutablesAsync();") \
        .replace("lifetime.", "patrolLifetime.").replace("message = ", "if (PatrolMaySpeak) message = ")
    same(member(new, "private async Task PatrolAsync(object cycle)"), patrol, "PatrolAsync", bad)
    nic = member(old, "private async Task PatrolNicAsync()") \
        .replace("lifetime.", "patrolLifetime.").replace("message = ", "if (PatrolMaySpeak) message = ")
    same(member(new, "private async Task PatrolNicAsync()"), nic, "PatrolNicAsync", bad)

    after_cancel = r"(?<![A-Za-z])lifetime\.Cancel\(\);\s*\n(?:\s*//[^\n]*\n)*\s*patrolLifetime\.Cancel\(\);"
    if not re.search(after_cancel, member(new, "public async Task DisconnectAsync()")):
        bad.append("DisconnectAsync 里 lifetime.Cancel(); 的下一行不是 patrolLifetime.Cancel();")
    if not re.search(after_cancel, member(new, "public void Dispose()")):
        bad.append("Dispose 里 lifetime.Cancel(); 的下一行不是 patrolLifetime.Cancel();")
    if not re.search(r"reapWarning = null;\s*\n(?:\s*//[^\n]*\n)*\s*SyncPatrol\(\);",
                     member(new, "private async Task<(UndoState State, string? Warning)> RemoveProtectionAsync()")):
        bad.append("RemoveProtectionAsync 里 reapWarning = null; 的下一行不是 SyncPatrol();")
    init = member(new, "public async Task InitializeAsync(")
    if not re.search(r'WriteJournal\("启动：接回断网保护，随后自动连接"\);\s*\n(?:\s*//[^\n]*\n)*\s*SyncPatrol\(\);', init):
        bad.append("InitializeAsync 里「接回断网保护」那一行的下一行不是 SyncPatrol();")
    for line in ROUTING_LOAD:
        if line not in init:
            bad.append(f"InitializeAsync 缺读代理范围的这一行:{line[:50]}")
    marks = [init.find("else if (keptMissing)"), init.find(ROUTING_LOAD[0]),
             init.find("await ExecuteAsync(machine.Handle(new(ConnectionEventKind.OperationFailed)));")]
    if -1 in marks or marks != sorted(marks):
        bad.append("读代理范围那一段要放在 keptMissing 那一路里、进入「需人工处理」之前")
    return bad


def tests_problems(new, old):
    bad = []
    declared = r"\[(?:Fact|Theory)[^\]\n]*\]\s*\n(?:\s*\[InlineData[^\n]*\n)*\s*public (async Task|void) (\w+)\("
    old_tests = re.findall(declared, old)
    if len(old_tests) < 50 or len(old_tests) != len(re.findall(r"^\s*\[(?:Fact|Theory)", old, flags=re.M)):
        bad.append("检查脚本没认全改动前的测试用例,请交 blocked 告诉派单方")
    for kind, name in old_tests:
        was, now = member(old, f"public {kind} {name}("), member(new, f"public {kind} {name}(")
        if not now:
            bad.append(f"既有用例 {name} 不见了(不许改名、不许删)")
        elif [l.strip() for l in was.splitlines() if "Assert." in l] != [l.strip() for l in now.splitlines() if "Assert." in l]:
            bad.append(f"既有用例 {name} 里带 Assert. 的行被改了")
    known = {name for _, name in old_tests}
    for name, tokens in NEW_TESTS.items():
        body = member(new, f"public async Task {name}(")
        if not body or name in known:
            bad.append(f"缺新用例 {name}")
            continue
        for token in tokens:
            if token not in body:
                bad.append(f"新用例 {name} 里没有契约要求的 {token}")
        if body.count("Assert.") < 3:
            bad.append(f"新用例 {name} 的断言太少")
    for token in ("private static async Task FireParkedPatrol(ClientController controller, Timers timers)",
                  "private sealed class FirstStartMissingTunnel(List<string> order) : ITunnelTransport"):
        if token not in new:
            bad.append(f"ControllerTests.cs 缺 {token}")
    if len(re.findall(declared, new)) < len(old_tests) + len(NEW_TESTS):
        bad.append(f"用例数不对:原有 {len(old_tests)} 个,现在 {len(re.findall(declared, new))} 个")
    if new.count("Skip") > old.count("Skip"):
        bad.append("ControllerTests.cs 里新增了跳过")
    return bad


def shape():
    return shape_problems(text(CONTROLLER), before(CONTROLLER))


def tests():
    return tests_problems(text(TESTS), before(TESTS))


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
