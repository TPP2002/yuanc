"""首次连接失败自动恢复与测试包开关单 yc-connect-abandon-testbuild-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
CONTROLLER = WIN / "WinClient.Core/Client/ClientController.cs"
RUNTIME = WIN / "WinClient.Core/Client/ClientRuntime.cs"
BUILD_INFO = WIN / "WinClient.Core/Client/BuildInfo.cs"
JOURNAL = WIN / "WinClient.Core/Client/ConnectJournal.cs"
DISABLED_KS = WIN / "WinClient.Core/Firewall/DisabledKillSwitch.cs"
DISABLED_NIC = WIN / "WinClient.Core/Network/DisabledNicGuard.cs"
MACHINE = WIN / "WinClient.Core/State/ConnectionStateMachine.cs"
SERVER = WIN / "WinClient.Core/Ipc/ControlServer.cs"
SERVICE = WIN / "WinClient.App/Hosting/ControlService.cs"
PRESENTATION = WIN / "WinClient.App/Presentation/StatusPresentation.cs"
CSPROJ = WIN / "WinClient.App/WinClient.App.csproj"
BUILD_SCRIPT = ROOT / "scripts/release/build-winclient.ps1"
T_CONTROLLER = WIN / "WinClient.Tests/ControllerTests.cs"
T_ABANDON = WIN / "WinClient.Tests/ConnectAbandonTests.cs"
T_STATE = WIN / "WinClient.Tests/StateTests.cs"
T_IPC = WIN / "WinClient.Tests/IpcTests.cs"
T_BUILD_INFO = WIN / "WinClient.Tests/BuildInfoTests.cs"
T_DISABLED = WIN / "WinClient.Tests/DisabledGuardTests.cs"
T_JOURNAL = WIN / "WinClient.Tests/ConnectJournalTests.cs"
T_STATUS = WIN / "WinClient.UiTests/StatusPresentationTests.cs"
DOC_GUARD = ROOT / "docs/winclient/断网保护加固说明.md"
DOC_RELEASE = ROOT / "docs/winclient/打包与发布说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Client/ClientController.cs",
    "winclient/WinClient.Core/Client/ClientRuntime.cs",
    "winclient/WinClient.Core/Client/BuildInfo.cs",
    "winclient/WinClient.Core/Client/ConnectJournal.cs",
    "winclient/WinClient.Core/Firewall/DisabledKillSwitch.cs",
    "winclient/WinClient.Core/Network/DisabledNicGuard.cs",
    "winclient/WinClient.Core/State/ConnectionStateMachine.cs",
    "winclient/WinClient.Core/Ipc/ControlServer.cs",
    "winclient/WinClient.App/Hosting/ControlService.cs",
    "winclient/WinClient.App/Presentation/StatusPresentation.cs",
    "winclient/WinClient.App/WinClient.App.csproj",
    "scripts/release/build-winclient.ps1",
    "winclient/WinClient.Tests/ControllerTests.cs",
    "winclient/WinClient.Tests/ConnectAbandonTests.cs",
    "winclient/WinClient.Tests/StateTests.cs",
    "winclient/WinClient.Tests/IpcTests.cs",
    "winclient/WinClient.Tests/BuildInfoTests.cs",
    "winclient/WinClient.Tests/DisabledGuardTests.cs",
    "winclient/WinClient.Tests/ConnectJournalTests.cs",
    "winclient/WinClient.UiTests/StatusPresentationTests.cs",
    "docs/winclient/断网保护加固说明.md",
    "docs/winclient/打包与发布说明.md",
}
RESTORED = "连接失败，已恢复原来的网络，当前没有走澳洲出口。"
NOT_RESTORED = "连接失败，原来的网络没能恢复：请点「断开」再试一次，还不行就重启电脑。"
TEST_BUILD_CUT = "测试包：出口核验不了，已自动断开并恢复原来的网络。"
REASONS = [
    "原因：系统过滤层的保护没能建立。",
    "原因：兜底路由没能建立。",
    "原因：没能关闭网卡「",
    "」的 IPv6。",
    "原因：系统防火墙没有开启，或被策略覆盖。",
    "原因：未找到连接内核。",
    "原因：有一步操作超过时限没有完成。",
    "原因：连续 4 次都没连上澳洲出口。",
    "原因已写入诊断记录，请导出诊断发给管理员。",
    "原因：出口核验不了。",
]
PHRASES = ["过滤层没建成", "兜底路由没建成", "网卡 IPv6 没关成", "系统防火墙没生效", "未找到连接内核", "操作超时",
           "连续 4 次没连上", "其他", "登录状态失效", "测试包出口核验不了"]
# 控制器里不许动的既有文字。
CONTROLLER_KEEP = [
    "未找到连接内核，请联系管理员配置 sing-box.exe 路径。",
    "操作失败，请联系管理员；断网保护没有自动撤销。",
    "连接内核未能停止，请联系管理员；断网保护保留。",
    "已断开，原网络设置已恢复。",
    "后台服务已重新启动，断网保护保持，正在恢复连接。",
    "internal static readonly TimeSpan ExitRecheckInterval = TimeSpan.FromMinutes(5);",
    "internal const int ExitCheckAttempts = 5;",
    "连接与断网保护保持,未自动断开。",
]
RENAMED = {
    "ApplyFailureDoesNotStartOrSilentlyRemoveProtection": "ApplyFailureOnFirstConnectRestoresNetworkWithoutStartingTunnel",
    "IneffectiveFirewallKeepsProtectionAndShowsSpecificReasonWithoutStartingTunnel": "IneffectiveFirewallOnFirstConnectRestoresNetworkAndNamesReason",
    "IneffectiveFirewallRejectsFirstConnectionAndRepeatedConnectionWithoutVerifiedProtection": "IneffectiveFirewallOnRepeatedFirstConnectRestoresEachTime",
    "FirstWfpFailureRefusesTunnelAndRequiresManualRecovery": "FirstWfpFailureRestoresNetworkAndNamesReason",
    "NicGuardFailureRefusesTunnelWhenNotHeld": "NicGuardFailureOnFirstConnectRestoresNetworkAndNic",
}
# 这些既有用例与本单相邻,名字必须原样还在。
CONTROLLER_UNTOUCHED = [
    "PairingRetriesReachManualWithAddressHintAndKeepProtection",
    "StartupAuthNetworkRetriesExhaustWithoutEverRemovingProtection",
    "RejectedSessionNeverStartsTunnel",
    "LeavingConnectedClearsExitEvenWhenStoppingThrows",
    "UnverifiableExitShowsHintAfterThreeRoundsWithoutDisconnecting",
    "HeldProtectionStartupKeepsTunnelAndWarnsWhenFirewallIsIneffective",
    "HeldProtectionKeepsTunnelWhenNicGuardFails",
    "FailedRecoveryNeedsManualAndExplainsPreservedRecord",
    "ReauthenticationKeepsTunnelAndWarnsWhenHeldProtectionCannotBeReapplied",
]
CONTROLLER_NEW = [
    "FirstConnectTunnelRetriesStopAfterThreeBackoffsAndRestoreNetwork",
    "FirstConnectAuthNetworkRetriesStopWithoutTouchingFirewall",
    "FirstConnectMissingKernelRestoresNetworkAndKeepsRestoreMessage",
    "HeldProtectionMissingKernelStillNeedsManualWithOriginalMessage",
    "FirstConnectApplyTimeoutRestoresNetworkAndNamesTimeout",
    "FirstConnectRestoreFailureNeedsManualKeepsProtectionAndTellsHowToRecover",
    "FirstConnectSessionExpiredAfterApplyDropsProtectionButKeepsNeedsLogin",
    "ReconnectAfterConnectedStillRetriesBeyondThreeBackoffs",
    "DisconnectDuringFirstAttemptUsesNormalDisconnectPath",
    "AbandonRaisesEventOnceAndWritesJournal",
    "TestBuildDisconnectsAndRestoresWhenExitCannotBeVerified",
    "TestBuildRechecksExitEveryMinute",
]
BASE_COUNTS = {  # 基线上的用例数,只许多不许少。
    "ControllerTests": (T_CONTROLLER, 66, 21),
    "IpcTests": (T_IPC, 22, 4),
    "StateTests": (T_STATE, 4, 2),
    "StatusPresentationTests": (T_STATUS, 3, 10),
}


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
    need(controller, [
        "internal const int FirstConnectRetries = 3;",
        "public event Action? AttemptAbandoned;",
        "public bool TestBuild { get; init; }",
        "public Action<string>? Journal { get; init; }",
        "internal static readonly TimeSpan TestBuildRecheckInterval = TimeSpan.FromMinutes(1);",
        "ConnectionEventKind.AttemptAbandoned",
        "ConnectJournal.Describe(",
        RESTORED, NOT_RESTORED, TEST_BUILD_CUT,
        " 已恢复原来的网络。", " 时区或浏览器设置未能恢复，请联系管理员。",
        "连接失败：", "连接失败：原因未知", "放弃并恢复：", "，撤销=", "不需要",
        *REASONS, *PHRASES, *CONTROLLER_KEEP,
    ], "ClientController.cs", bad)
    machine = text(MACHINE)
    need(machine, ["AttemptAbandoned", "连接操作失败，断网保护未主动撤销，请联系管理员。",
                   "多次重连仍未成功，请联系管理员。断网保护仍保持。", "private static readonly int[] BackoffSeconds = [2, 4, 8, 16, 32, 60];",
                   "if (capRetriesScheduled >= 6)"], "ConnectionStateMachine.cs", bad)
    server = text(SERVER)
    need(server, ["public static bool ShouldStayConnected(ClientSnapshot snapshot)",
                  "desired.Write(ShouldStayConnected(facade.Snapshot));", "desired.Write(false);"], "ControlServer.cs", bad)
    if "desired.Write(true);" in server:
        bad.append("ControlServer.cs 的 connect 分支不许再无条件写 true")
    service = text(SERVICE)
    need(service, ["BuildInfo.TestBuild", "BuildInfo.KeepOnStartup(", "testBuild:", "AttemptAbandoned +=", "desired.Write(false)",
                   "测试包：断网保护已关闭，开机不自动连接。"], "ControlService.cs", bad)
    if "desired.Read() != false" in service:
        bad.append("ControlService.cs 应改用 BuildInfo.KeepOnStartup 判断开机是否保持保护")
    need(text(BUILD_INFO), ['public const string TestBuildKey = "YuanC.TestBuild";',
                            "internal static bool IsTestBuild(IEnumerable<", "public static bool IsTestBuild(",
                            "GetEntryAssembly()", "public static bool KeepOnStartup(bool testBuild, bool? desired) => !testBuild && desired != false;"],
         "BuildInfo.cs", bad)
    need(text(JOURNAL), ["public static class ConnectJournal", "public static string Describe(Exception ex)", "[地址]", "[用户]", " <- ", " | "],
         "ConnectJournal.cs", bad)
    disabled = text(DISABLED_KS)
    need(disabled, ["public sealed class DisabledKillSwitch(IKillSwitch inner) : IKillSwitch", "PatrolReport.Empty",
                    "inner.RecoverAsync()", "inner.RemoveAsync()", "inner.HasPendingState", "inner.PendingMode"], "DisabledKillSwitch.cs", bad)
    for word in ("inner.ApplyAsync", "inner.ApplyAppsAsync", "inner.UpdateNodeAsync", "inner.PatrolAsync"):
        if word in disabled:
            bad.append("DisabledKillSwitch.cs 不许把套用、换节点、巡检转给真执行器:" + word)
    nic = text(DISABLED_NIC)
    need(nic, ["public sealed class DisabledNicGuard(INicGuard inner) : INicGuard", "inner.RestoreAsync()", "inner.HasPendingState"],
         "DisabledNicGuard.cs", bad)
    for word in ("inner.ApplyAsync", "inner.PatrolAsync", "inner.PublicIpv4Adapter"):
        if word in nic:
            bad.append("DisabledNicGuard.cs 只许转发恢复:" + word)
    need(text(RUNTIME), ["bool testBuild = false", "internal static IKillSwitch GuardFor(IKillSwitch real, bool testBuild)",
                         "new DisabledNicGuard(", "connect.log", "Journal =", "TestBuild = testBuild",
                         "try { await firewall.RecoverAsync(); }"], "ClientRuntime.cs", bad)
    presentation = text(PRESENTATION)
    need(presentation, ["bool? testBuild = null", "BuildInfo.TestBuild", "测试包已关闭,断线时会直连", "澳洲出口客户端(测试包) · ",
                        "澳洲出口客户端 · ", "未启用,连接时自动开启", "正常,每 60 秒巡检一次", "保持中(到期后不撤)"],
         "StatusPresentation.cs", bad)
    need(text(CSPROJ), ["'$(YuanCTestBuild)' == 'true'", '<AssemblyMetadata Include="YuanC.TestBuild" Value="true" />'], "WinClient.App.csproj", bad)
    need(text(BUILD_SCRIPT), ["param([string]$Version, [switch]$TestBuild)", "-p:YuanCTestBuild=true", "-test",
                              "测试包：断网保护已关闭，不能交给客户。", "$start.CreateNoWindow = $true", "$start.UseShellExecute = $false",
                              "'YuanC-Client-' + $Version"], "build-winclient.ps1", bad)
    fail(bad)


def tests():
    bad = []
    controller = text(T_CONTROLLER)
    both = controller + "\n" + text(T_ABANDON)
    for old, new in RENAMED.items():
        if " " + old + "(" in controller:
            bad.append("ControllerTests 旧用例名还在:" + old)
        if " " + new + "(" not in controller:
            bad.append("ControllerTests 缺改名后的用例 " + new)
    for name in CONTROLLER_UNTOUCHED:
        if " " + name + "(" not in controller:
            bad.append("ControllerTests 既有用例缺失或改了名:" + name)
    for name in CONTROLLER_NEW:
        if " " + name + "(" not in both:
            bad.append("缺新用例 " + name + "(写在 ControllerTests.cs 或 ConnectAbandonTests.cs)")
    need(controller, [
        "new Firewall(order) { HasPendingState = true }, new PairingTests.FakeTunnel(order, fail: true)",
        'Assert.Equal(12, order.Count(x => x == "start"));',
        'Assert.Contains("重新导出配对文件再导入", result.Message);',
        "原因：系统防火墙没有开启，或被策略覆盖。", "原因：系统过滤层的保护没能建立。", "原因：没能关闭网卡「以太网」的 IPv6。",
    ], "ControllerTests(六个改过的用例)", bad)
    if controller.count("foreach (var seconds in new[] { 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60 })") != 2:
        bad.append("ControllerTests 里两处 11 次退避的循环都要原样保留")
    need(both, [RESTORED, NOT_RESTORED, TEST_BUILD_CUT, "原因：连续 4 次都没连上澳洲出口。", "原因：未找到连接内核。",
                "原因：有一步操作超过时限没有完成。", "登录已到期，请重新登录。 已恢复原来的网络。",
                "放弃并恢复：系统防火墙没生效，撤销=成功", "放弃并恢复：测试包出口核验不了，撤销=成功",
                "未找到连接内核，请联系管理员配置 sing-box.exe 路径。", "已断开，原网络设置已恢复。"],
         "控制器新用例", bad)
    need(text(T_STATE), [" AttemptAbandonedReturnsToDisconnectedWithOnlyStopTunnel(", "ConnectionEventKind.AttemptAbandoned"], "StateTests", bad)
    ipc = text(T_IPC)
    need(ipc, [" ConnectWritesDesiredFromResultingSnapshot(", "Assert.True(desired.Read());", "Assert.False(desired.Read());"], "IpcTests", bad)
    if ipc.count("Assert.True(desired.Read());") < 2:
        bad.append("IpcTests 既有的两处 Assert.True(desired.Read()) 不许删")
    need(text(T_BUILD_INFO), [" KeepOnStartupTruthTable(", " IsTestBuildReadsMetadata(", "YuanC.TestBuild"], "BuildInfoTests", bad)
    need(text(T_DISABLED), [" DisabledKillSwitchNeverAppliesOrPatrolsButStillRecoversAndRemovesLeftovers(", " DisabledNicGuardOnlyRestores(",
                            " GuardForWrapsOnlyInTestBuild(", "ClientRuntime.GuardFor("], "DisabledGuardTests", bad)
    need(text(T_JOURNAL), [" DescribeChainsTypesAndScrubsAddressesAndUserFolders(",
                           "InvalidOperationException：外层 [地址] <- IOException：", "[用户]", " | 第二行", "203.0.113.9", "alice"],
         "ConnectJournalTests", bad)
    need(text(T_STATUS), [" TestBuildGuardRowAndTrayTextAreMarked(", "测试包已关闭,断线时会直连", "澳洲出口客户端(测试包) · ", "testBuild: true",
                          "testBuild: false"], "StatusPresentationTests", bad)
    for name, (path, facts, theories) in BASE_COUNTS.items():
        body = text(path)
        if body.count("[Fact]") < facts or body.count("[Theory]") < theories:
            bad.append(f"{name} 的用例数比基线少(基线 [Fact] {facts}、[Theory] {theories})")
    for path in (T_ABANDON, T_BUILD_INFO, T_DISABLED, T_JOURNAL):
        body = text(path)
        for word in ("WfpEngine.CreateProduction", "new RouteGuard(", "new KillSwitchApplier(", "new NicGuard(", "ProcessStartInfo"):
            if word in body:
                bad.append(f"{path.name} 不许碰真系统:{word}")
    fail(bad)


def docs():
    bad = []
    guard = text(DOC_GUARD)
    need(guard, ["## 首次连接失败自动恢复", "## 测试包(断网保护关闭)", RESTORED, NOT_RESTORED, TEST_BUILD_CUT,
                 "自动恢复原来的网络", "不建，继续用国内的，但是先把断网保护给禁用", "2026-11-27",
                 "防泄漏相关的验收项在测试包上一律不算通过", "真机待验证", "期望状态", "1 分钟", "开机不自动连接",
                 "测试包已关闭,断线时会直连", "连续 4 次",
                 "任何出口核验或巡检结果都不自动断开隧道，也不自动撤销断网保护。", "测试包除外",
                 "## 服务重启时保持保护", "## 已持有保护时防火墙失效:保持隧道并告警", "## 系统过滤层第二道闸(WFP)"],
         "断网保护加固说明.md", bad)
    for stale in ("首次连接拒绝启动隧道，进入需人工处理，透出原文",
                  "失败后再次点击连接也不会把部分安装当成验证成功：仍进入需人工处理"):
        if stale in guard:
            bad.append("断网保护加固说明.md 还留着旧口径:" + stale)
    need(text(DOC_RELEASE), ["-TestBuild", "YuanC-Client-<Version>-test.exe", "不能交给客户", "断网保护", "不签名", "更新源",
                             "## 维护人员出包", "安装包大小不设硬上限"], "打包与发布说明.md", bad)
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
