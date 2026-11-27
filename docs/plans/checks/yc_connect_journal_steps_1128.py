"""连接过程逐步记录单 yc-connect-journal-steps-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
CONTROLLER = WIN / "WinClient.Core/Client/ClientController.cs"
JOURNAL = WIN / "WinClient.Core/Client/ConnectJournal.cs"
T_FLOW = WIN / "WinClient.Tests/ConnectJournalFlowTests.cs"
DOC_JOURNAL = ROOT / "docs/winclient/连接记录说明.md"
DOC_GUARD = ROOT / "docs/winclient/断网保护加固说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Client/ClientController.cs",
    "winclient/WinClient.Core/Client/ConnectJournal.cs",
    "winclient/WinClient.Tests/ConnectJournalFlowTests.cs",
    "docs/winclient/连接记录说明.md",
    "docs/winclient/断网保护加固说明.md",
}
# 控制器里必须出现的记录行字样(插值写法也要保留这些连续片段)。
LINES = [
    "连接请求：来源=", "，恢复记录=", "读不到",
    "连接未开始：", "未配置服务器", "已在连接或已连接", "指定程序名单为空", "恢复记录与代理范围不一致",
    "读不到网卡地址", "网卡上有公网 IPv4", "浏览器正在运行，等用户再点一次",
    "开始连接：模式=", "，代理范围=", "全部流量", "仅指定程序 ", "，首次尝试=",
    "连接请求结束：状态=",
    "取会话：", "取会话：会话或账号已到期", "续期：",
    "状态：", "→",
    "动作开始：", "动作结束：", "动作出错：", "，用时 ", " 毫秒",
    "启动隧道没成功：", "套用断网保护没成功，隧道保持：", "隧道掉线",
    "出口核验：已核验", "出口核验：不一致", "出口核验：第 ", " 次没有回应", "出口核验：无法核验，已连续 ", " 轮",
    "断开未开始：浏览器正在运行，等用户再点一次", "断开请求：状态=", "断开完成：环境恢复=",
    "启动：保持保护=", "，自动连接=", "，模式=", "启动：接回断网保护，随后自动连接", "启动：已做启动恢复，提醒=",
    "巡检：", "巡检：恢复正常", "已为新出现的",
    "停止隧道没成功：", "撤销断网保护没成功：", "恢复网卡没成功：", "恢复环境没成功：",
]
# 上一张单定死、本单不许动的原文。
KEPT = [
    'private const string AbandonRestored = "连接失败，已恢复原来的网络，当前没有走澳洲出口。";',
    'private const string AbandonNotRestored = "连接失败，原来的网络没能恢复：请点「断开」再试一次，还不行就重启电脑。";',
    'private const string TestBuildDisconnected = "测试包：出口核验不了，已自动断开并恢复原来的网络。";',
    'message = "操作失败，请联系管理员；断网保护没有自动撤销。";',
    "private static bool IsOperational(Exception ex) => ex is IOException or UnauthorizedAccessException or",
    "System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or",
    "InvalidOperationException or ArgumentException or TimeoutException or System.ComponentModel.Win32Exception or OperationCanceledException;",
    "internal const int FirstConnectRetries = 3;",
    "internal static readonly TimeSpan TestBuildRecheckInterval = TimeSpan.FromMinutes(1);",
    "internal static readonly TimeSpan ExitRecheckInterval = TimeSpan.FromMinutes(5);",
    "internal static readonly TimeSpan PatrolInterval = TimeSpan.FromSeconds(60);",
    '"连接失败："', '"放弃并恢复："', "public event Action? AttemptAbandoned;",
]
STATE_NAMES = ["未连接", "连接中", "已连接", "重连中", "需重新登录", "需人工处理"]
EFFECT_NAMES = ["套用断网保护", "更新节点规则", "撤销断网保护", "停止隧道", "启动隧道", "显示提示", "安排退避 "]
TEST_NAMES = [
    "StateAndEffectNamesAreFixed", "CleanScrubsLikeDescribe", "SuccessfulConnectWritesRequestSessionActionsAndStates",
    "RejectedConnectWritesReason", "TunnelStartFailureWritesReasonAndBackoff", "SessionResultNameIsWritten",
    "ExitCheckWritesRoundsWithoutAddress", "DisconnectWritesRequestAndResult", "InitializeWritesStartupBranch",
    "PatrolWritesOnlyChangesFromNormal", "UnexpectedExceptionOnFirstConnectStillRestoresNetwork",
    "UnexpectedExceptionWithHeldProtectionStillPropagates",
    "UnexpectedRemoveFailureDuringAbandonNeedsManualAndKeepsProtection",
    "UnexpectedExceptionInBackoffCallbackOnFirstAttemptRestores", "JournalSubscriberFailureDoesNotBreakConnect",
]
TEST_WORDS = [
    "连接请求：来源=用户，状态=未连接，保护=无，恢复记录=无",
    "开始连接：模式=自用模式，代理范围=全部流量，首次尝试=是",
    "状态：未连接→连接中", "取会话：Ok", "取会话：Network", "动作开始：套用断网保护", "动作结束：套用断网保护，用时 ",
    "动作开始：启动隧道", "状态：连接中→已连接", "动作结束：启动隧道，用时 ", "连接请求结束：状态=已连接，保护=有",
    "连接未开始：未配置服务器", "连接未开始：已在连接或已连接", "连接未开始：恢复记录与代理范围不一致",
    "启动隧道没成功：IOException：测试断线", "动作开始：安排退避 2 秒", "状态：连接中→重连中",
    "出口核验：已核验", "出口核验：第 1 次没有回应", "出口核验：第 4 次没有回应", "出口核验：无法核验，已连续 1 轮",
    "TestData.Node().Host",
    "断开请求：状态=已连接，保护=有", "动作开始：停止隧道", "动作开始：撤销断网保护", "状态：已连接→未连接",
    "断开完成：环境恢复=成功",
    "启动：保持保护=否，自动连接=否，恢复记录=无，模式=自用模式", "启动：已做启动恢复，提醒=无",
    "启动：接回断网保护，随后自动连接",
    "巡检：系统防火墙已被关闭或被策略覆盖", "巡检：恢复正常", "PatrolReport.Empty",
    "连接失败，已恢复原来的网络，当前没有走澳洲出口。原因已写入诊断记录，请导出诊断发给管理员。",
    "动作出错：套用断网保护，用时 ", "NotSupportedException：意外", "连接失败：NotSupportedException：意外",
    "Assert.ThrowsAsync<NotSupportedException>",
    "连接失败，原来的网络没能恢复：请点「断开」再试一次，还不行就重启电脑。原因：系统过滤层的保护没能建立。",
    "撤销断网保护没成功：NotSupportedException：撤销意外",
    "ConnectJournal.StateName(", "ConnectJournal.EffectName(", "ConnectJournal.Clean(", "安排退避 8 秒", "[地址]", "[用户]",
]
DOC_WORDS = [
    "run/connect.log", "连接请求：来源=", "连接未开始：", "开始连接：模式=", "连接请求结束：状态=", "取会话：", "续期：",
    "状态：", "动作开始：", "动作结束：", "动作出错：", "启动隧道没成功：", "套用断网保护没成功，隧道保持：", "隧道掉线",
    "出口核验：已核验", "出口核验：不一致", "次没有回应", "出口核验：无法核验，已连续", "断开未开始：", "断开请求：状态=",
    "断开完成：环境恢复=", "启动：保持保护=", "启动：接回断网保护，随后自动连接", "启动：已做启动恢复，提醒=", "巡检：",
    "巡检：恢复正常", "停止隧道没成功：", "撤销断网保护没成功：", "恢复网卡没成功：", "恢复环境没成功：", "连接失败：",
    "放弃并恢复：", "节点地址", "出口地址", "令牌", "配对内容", "导出诊断", "真机待验证（本单未执行）",
]
NEW_TRIGGER = "首次尝试期间任何一步抛出异常（不限类型）或走到失败处理（套用断网保护失败或超时、内核起不来等）。"
OLD_TRIGGER = "首次尝试期间任何一步走到失败处理（套用断网保护失败或超时、内核起不来、其他可处理异常）。"
POINTER = "记录里不出现节点地址、出口地址、令牌或配对内容。连接过程其余各步的记录格式见[连接记录说明](连接记录说明.md)。"


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


def shape():
    bad = []
    controller = text(CONTROLLER)
    need(controller, LINES, "ClientController.cs", bad)
    need(controller, KEPT, "ClientController.cs(不许动的原文)", bad)
    need(controller, ["ConnectJournal.StateName(", "ConnectJournal.EffectName(", "ConnectJournal.Clean(", "ConnectJournal.Describe(",
                      "System.Diagnostics.Stopwatch", "firewall.HasPendingState"], "ClientController.cs", bad)
    if controller.count("catch (Exception ex) when (firstAttempt)") != 2:
        bad.append("ClientController.cs 里 catch (Exception ex) when (firstAttempt) 必须恰好两处(ConnectAsync 与 RunScheduledAsync)")
    if controller.count("catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }") < 4:
        bad.append("ClientController.cs 原有的 catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); } 不许删")
    if "using System.Diagnostics;" in controller:
        bad.append("ClientController.cs 不许加 using System.Diagnostics;(计时类写全名)")
    for word in ("Node.Host +", "exitIp +", "Hy2Password", "Uuid +", "RealityPublicKey +"):
        if "WriteJournal(" in controller and any(word in line for line in controller.split("\n") if "WriteJournal(" in line):
            bad.append("ClientController.cs 的记录行里不许写 " + word)
    journal = text(JOURNAL)
    need(journal, ["public static string Describe(Exception ex)", "public static string Clean(string? message)",
                   "public static string StateName(ConnectionState state)", "public static string EffectName(ConnectionEffect effect)",
                   "internal const int MaxDepth = 4;", "internal const int MaxMessageLength = 300;", "[地址]", "[用户]",
                   *STATE_NAMES, *EFFECT_NAMES], "ConnectJournal.cs", bad)
    if "private static string Clean(" in journal:
        bad.append("ConnectJournal.cs 的 Clean 要改成公开")
    fail(bad)


def tests():
    bad = []
    body = text(T_FLOW)
    if not body:
        fail(["缺测试文件 ConnectJournalFlowTests.cs"])
    for name in TEST_NAMES:
        if " " + name + "(" not in body:
            bad.append("ConnectJournalFlowTests.cs 缺用例 " + name)
    need(body, TEST_WORDS, "ConnectJournalFlowTests.cs", bad)
    for word in ("new CommandRunner(", "Process.Start(", "ClientSettings.DataDirectory", "WfpEngine.CreateProduction",
                 "new KillSwitchApplier(", "new RollingFileLog(", "ClientRuntime.CreateAsync("):
        if word in body:
            bad.append("ConnectJournalFlowTests.cs 不许碰真系统:" + word)
    fail(bad)


def docs():
    bad = []
    doc = text(DOC_JOURNAL)
    if not doc:
        bad.append("缺文档 docs/winclient/连接记录说明.md")
    else:
        need(doc, DOC_WORDS, "连接记录说明.md", bad)
        for name in STATE_NAMES:
            if name not in doc:
                bad.append("连接记录说明.md 缺状态名 " + name)
    guard = text(DOC_GUARD)
    need(guard, [NEW_TRIGGER, POINTER, "## 首次连接失败自动恢复", "## 测试包(断网保护关闭)",
                 "本来要安排第 4 次退避时（前 3 次照常，间隔 2、4、8 秒）不再安排。"], "断网保护加固说明.md", bad)
    if OLD_TRIGGER in guard:
        bad.append("断网保护加固说明.md 还留着旧的第 1 条触发点")
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
