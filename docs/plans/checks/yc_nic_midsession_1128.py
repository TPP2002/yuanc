"""工单 yc-nic-midsession-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTROLLER = "winclient/WinClient.Core/Client/ClientController.cs"
RUNTIME = "winclient/WinClient.Core/Client/ClientRuntime.cs"
SOURCE = "winclient/WinClient.Core/Network/AddressChangeSource.cs"
TESTS = "winclient/WinClient.Tests/ControllerTests.cs"
SOURCE_TESTS = "winclient/WinClient.Tests/AddressChangeSourceTests.cs"
ALLOWED = {CONTROLLER, RUNTIME, SOURCE, TESTS, SOURCE_TESTS}

# 这些方法的正文一个字不能变(和改动前逐字比)。
UNTOUCHED = [
    'private void Schedule(TimeSpan delay, Func<Task> action, string purpose = "")',
    "private async Task RunScheduledAsync(",
    "private async Task FailAsync(",
    "private async Task AbandonAsync(",
    "private async Task<(UndoState State, string? Warning)> RemoveProtectionAsync()",
    "private async Task MaybeAbandonAfterLoginFailureAsync()",
    "public async Task InitializeAsync(",
    "internal async Task ConnectAsync(bool fromUser)",
    "public async Task DisconnectAsync()",
    "public async Task RefreshSessionAsync()",
    "public async Task ChangeSessionSourceAsync(",
    "private async Task ExecuteAsync(Transition transition)",
    "private async Task FetchSessionAsync()",
    "private async Task ApplySessionAsync(",
    "private async Task RenewAsync(",
    "private async Task CheckExitAsync(",
    "private async Task CheckEnvironmentAsync(",
    "private async Task<string?> PatrolNewExecutablesAsync()",
    "private void JournalPatrol()",
    "private void UpdateMonitoring()",
    "private void SyncPatrol()",
    "private void SchedulePatrol(object cycle)",
    "private async Task RunPatrolAsync(object cycle, CancellationToken token)",
    "private async Task PatrolAsync(object cycle)",
    "private void ReapStaleConnections()",
]
LINES = [
    "internal static readonly TimeSpan NicSweepDelay = TimeSpan.FromSeconds(2);",
    "private int nicSweepQueued;",
    "private Task PatrolNicAsync() => TightenNicAsync(fromPatrol: true);",
    "internal static string PublicIpv4ParkedMessage(string adapter, bool apps)",
    "internal static string PublicIpv4GuardStatus(string adapter)",
    "addressChanges: addressChanges",
]
# 定稿的字,一字不差。
TEXTS = [
    "上出现了公网 IPv4 地址(通常是电脑自己拨号上网,或换了网络),部分软件和网页可以直接读到这个地址,已停止连接。断网保护保持,",
    "暂时上不了网。请点「断开」恢复原来的网络,改由路由器拨号上网后再连接,或联系管理员。",
    '"名单里的程序"',
    '"电脑"',
    "出现公网 IPv4 地址,连接已停止,断网保护保持",
    "原因：网卡「{adapter}」上出现了公网 IPv4 地址。",
    # 连接前拒连那句不许动。
    "上直接有公网 IPv4 地址(通常是电脑自己拨号上网),部分软件和网页可以直接读到这个地址,已拒绝连接。请改由路由器拨号上网后再连接,或联系管理员。",
]
OLD_HINT = "连接与断网保护保持,请改由路由器拨号或联系管理员"
MEMBERS = {
    "private async Task TightenNicAsync(bool fromPatrol)": (
        ["nicGuard.PatrolAsync(patrolLifetime.Token)", "ParkForPublicIpv4Async(", "fromPatrol", "已关闭新出现公网 IPv6 的网卡"],
        ["lifetime.Cancel", "RemoveAsync", "RestoreAsync"]),
    "private async Task ParkForPublicIpv4Async(string adapter)": (
        ["firstAttempt", "AbandonAsync(", "lifetime.Cancel();", "ConnectionEventKind.OperationFailed",
         "PublicIpv4ParkedMessage(", "PublicIpv4GuardStatus(",
         "ConnectionState.Connecting", "ConnectionState.Connected", "ConnectionState.Reconnecting"],
        ["RemoveAsync", "UserDisconnect", "RemoveProtectionAsync", "RestoreAsync", "patrolLifetime.Cancel"]),
    "private void OnAddressChanged()": (
        ["Interlocked.Exchange(ref nicSweepQueued, 1)", "RunNicSweepAsync(patrolLifetime.Token)", "protection"],
        ["gate.", "nicGuard.PatrolAsync", "nicGuard.ApplyAsync", "await ", "Task.Run"]),
    "private async Task RunNicSweepAsync(CancellationToken token)": (
        ['DelayForPurposeAsync(NicSweepDelay, token, "网卡收紧")', "gate.WaitAsync(token)", "TightenNicAsync(fromPatrol: false)",
         "gate.Release()", "Publish()", "nicSweepQueued, 0)"],
        ["Task.Delay", "Schedule("]),
    "public void Dispose()": (["Changed -= OnAddressChanged"], []),
}
SOURCE_TOKENS = [
    "namespace WinClient.Core.Network;",
    "public interface IAddressChangeSource",
    "event Action? Changed;",
    "public sealed class SystemAddressChangeSource : IAddressChangeSource, IDisposable",
    "NetworkChange.NetworkAddressChanged += ",
    "NetworkChange.NetworkAddressChanged -= ",
]
RUNTIME_LINE = "addressChanges: testBuild ? null : new SystemAddressChangeSource(),"
CASE_START = "case EffectKind.ApplyKillSwitch:"
CASE_END = "case EffectKind.UpdateKillSwitchNode:"
RENAMED = {"PatrolReportsNewPublicIpv4AdapterWithoutDisconnect": "PatrolDisablesNewIpv6AdapterAndReportsNicFailure"}
NEW_TESTS = {
    "PatrolDisablesNewIpv6AdapterAndReportsNicFailure": ['"正常,已关闭新出现公网 IPv6 的网卡 1 个"', '"巡检失败文案"', "ConnectionState.Connected"],
    "PublicIpv4MidSessionStopsTunnelAndKeepsProtection": ["FireParkedPatrol(", "PublicIpv4ParkedMessage(", "PublicIpv4GuardStatus(",
                                                          "ConnectionState.NeedsManual", '"remove"', '"stop"'],
    "ParkedPatrolReportsPublicIpv4InStatusOnly": ["FireParkedPatrol(", "PublicIpv4GuardStatus(", "tunnel.FailStop = true"],
    "PublicIpv4DuringFirstAttemptRestoresNetwork": ["FakeAddressChanges", "Raise()", "原因：网卡「拨号连接」上出现了公网 IPv4 地址。",
                                                    "ConnectionState.Disconnected", '"remove"'],
    "AddressChangeTightensNicWithinSeconds": ["FakeAddressChanges", "Raise()", '"网卡收紧"', "NicSweepDelay",
                                              '"已关闭新出现公网 IPv6 的网卡 1 个"', "ConnectionState.Connected"],
    "AddressChangeParksOnPublicIpv4": ["FakeAddressChanges", "Raise()", "PublicIpv4ParkedMessage(", "ConnectionState.NeedsManual"],
    "AddressChangeIgnoredWithoutProtection": ["FakeAddressChanges", "Raise()", '"网卡收紧"', "Assert.Empty("],
    "DisposeUnsubscribesAddressChanges": ["FakeAddressChanges", "Subscribers", "Disposed"],
    "HeldFirewallFailureStillTightensNic": ['"nic-apply"', "WfpUnavailableException", "keepProtection: true", '"reap"'],
    "HeldFirewallAndNicFailuresBothReported": ["WfpUnavailableException", "NicGuardException", "keepProtection: true"],
}
SKIPS = r"\bSkip\s*=|\bAssert\.Skip\w*\s*\(|\bSkip\.If\w*\s*\(|\bSkippable(?:Fact|Theory)\b"
REAL_WAITS = r"\bTask\.Delay\s*\(|\bThread\.Sleep\s*\("
DECLARED = r"\[(?:Fact|Theory)[^\]\n]*\]\s*\n(?:\s*\[InlineData[^\n]*\n)*\s*public (async Task|void) (\w+)\("


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


def without_case(effects):
    """把 ExecuteEffectsAsync 里「套用断网保护」那一个分支挖掉,剩下的拿去逐字比。"""
    start, end = effects.find(CASE_START), effects.find(CASE_END)
    return None if start < 0 or end < start else effects[:start] + effects[end:]


def controller_problems(new, old):
    bad = []
    for line in LINES:
        if line not in new:
            bad.append(f"ClientController.cs 缺这一行或写法与契约不一致:{line[:70]}")
    for words in TEXTS:
        if words not in new:
            bad.append(f"ClientController.cs 缺定稿的字(一字不差):{words[:40]}…")
    if OLD_HINT in new:
        bad.append("ClientController.cs 里还留着旧提示「连接与断网保护保持,请改由路由器拨号或联系管理员」")
    if new.count("IAddressChangeSource? addressChanges = null") != 2:
        bad.append("两个构造函数都要在参数表最后加 IAddressChangeSource? addressChanges = null")
    if "addressChanges.Changed += OnAddressChanged" not in new:
        bad.append("构造函数里要订阅 addressChanges.Changed += OnAddressChanged")

    for signature in UNTOUCHED:
        was, now = member(old, signature), member(new, signature)
        if not was:
            bad.append(f"检查脚本在改动前的代码里找不到 {signature},请交 blocked 告诉派单方")
        elif was != now:
            bad.append(f"不许动的方法被改了:{signature}")

    for signature, (needed, forbidden) in MEMBERS.items():
        body = member(new, signature)
        if not body:
            bad.append(f"缺 {signature}")
            continue
        for token in needed:
            if token not in body:
                bad.append(f"{signature} 里没有契约要求的 {token}")
        for token in forbidden:
            if token in body:
                bad.append(f"{signature} 里不许出现 {token}")

    effects_old = member(old, "private async Task ExecuteEffectsAsync(Transition transition)")
    effects_new = member(new, "private async Task ExecuteEffectsAsync(Transition transition)")
    if without_case(effects_old) is None:
        bad.append("检查脚本在改动前的 ExecuteEffectsAsync 里找不到套用断网保护那个分支,请交 blocked 告诉派单方")
    elif without_case(effects_new) != without_case(effects_old):
        bad.append("ExecuteEffectsAsync 里「套用断网保护」以外的分支被改了")
    else:
        case = effects_new[effects_new.find(CASE_START):effects_new.find(CASE_END)]
        marks = [case.find("catch (FirewallIneffectiveException ex) when (held)"),
                 case.find("nicGuard.ApplyAsync(lifetime.Token)"),
                 case.find("catch (NicGuardException ex) when (held)")]
        if -1 in marks or marks != sorted(marks):
            bad.append("套用断网保护那个分支:网卡收紧要放在防火墙那步的 catch 之后,并有自己的 catch (NicGuardException ex) when (held)")
        if case.count("nicGuard.ApplyAsync(") != 1 or case.count("ReapStaleConnections();") != 1:
            bad.append("套用断网保护那个分支:nicGuard.ApplyAsync 和 ReapStaleConnections 各只许出现一次")
        for token in ("var held = protectionVerified;", "protection = true;", "protectionVerified = true;",
                      "firewallApplied", "WfpKeepTunnelWarning", "RouteKeepTunnelWarning", "KeepTunnelWarning", "NicKeepTunnelWarning("):
            if token not in case:
                bad.append(f"套用断网保护那个分支里没有 {token}")
    return bad


def source_problems(new):
    bad = [f"AddressChangeSource.cs 缺 {token}" for token in SOURCE_TOKENS if token not in new]
    for token in ("Task.Run", "Thread", "IPAddress", "GetAllNetworkInterfaces"):
        if token in new:
            bad.append(f"AddressChangeSource.cs 里不许出现 {token}:它只转发一个信号,不读地址、不起线程")
    return bad


def runtime_problems(new, old):
    kept = [line for line in new.splitlines() if RUNTIME_LINE not in line]
    if new.count(RUNTIME_LINE) != 1:
        return [f"ClientRuntime.cs 要正好加一行:{RUNTIME_LINE}"]
    return [] if kept == old.splitlines() else ["ClientRuntime.cs 除了加的那一行,别的不许动"]


def shape_problems(controller, controller_old, source, runtime, runtime_old):
    return controller_problems(controller, controller_old) + source_problems(source) + runtime_problems(runtime, runtime_old)


def tests_problems(new, old, source_tests):
    bad = []
    old_tests = re.findall(DECLARED, old)
    if len(old_tests) < 50 or len(old_tests) != len(re.findall(r"^\s*\[(?:Fact|Theory)", old, flags=re.M)):
        bad.append("检查脚本没认全改动前的测试用例,请交 blocked 告诉派单方")
    for kind, name in old_tests:
        was, now = member(old, f"public {kind} {name}("), member(new, f"public {kind} {name}(")
        if name in RENAMED:
            if now:
                bad.append(f"旧用例 {name} 断言的是旧行为,要按契约改名为 {RENAMED[name]}")
        elif not now:
            bad.append(f"既有用例 {name} 不见了(不许改名、不许删)")
        elif [line.strip() for line in was.splitlines() if "Assert." in line] != [line.strip() for line in now.splitlines() if "Assert." in line]:
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
    if "private sealed class FakeAddressChanges : IAddressChangeSource, IDisposable" not in new:
        bad.append("ControllerTests.cs 缺 private sealed class FakeAddressChanges : IAddressChangeSource, IDisposable")
    if len(re.findall(DECLARED, new)) < len(old_tests) - len(RENAMED) + len(NEW_TESTS):
        bad.append(f"用例数不对:原有 {len(old_tests)} 个,现在 {len(re.findall(DECLARED, new))} 个")
    if len(re.findall(SKIPS, new)) > len(re.findall(SKIPS, old)):
        bad.append("ControllerTests.cs 里新增了跳过")
    if len(re.findall(REAL_WAITS, new)) > len(re.findall(REAL_WAITS, old)):
        bad.append("ControllerTests.cs 里新增了真的等时间(Task.Delay / Thread.Sleep);用 Timers 触发")
    for token in ("public class AddressChangeSourceTests", "public void SystemSourceSubscribesAndDisposesCleanly()",
                  "new SystemAddressChangeSource()", "Dispose()", "Assert."):
        if token not in source_tests:
            bad.append(f"AddressChangeSourceTests.cs 缺 {token}")
    if re.search(SKIPS, source_tests) or re.search(REAL_WAITS, source_tests):
        bad.append("AddressChangeSourceTests.cs 里不许跳过、不许真的等时间")
    return bad


def shape():
    return shape_problems(text(CONTROLLER), before(CONTROLLER), text(SOURCE), text(RUNTIME), before(RUNTIME))


def tests():
    return tests_problems(text(TESTS), before(TESTS), text(SOURCE_TESTS))


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
