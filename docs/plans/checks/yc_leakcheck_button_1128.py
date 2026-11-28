"""工单 yc-leakcheck-button-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CORE = "winclient/WinClient.Core/"
APP = "winclient/WinClient.App/"
PLAN = CORE + "Diagnostics/LeakCheckPlan.cs"
SERVICE = CORE + "Diagnostics/LeakCheckService.cs"
FORMATTER = CORE + "Diagnostics/LeakReportFormatter.cs"
CAPTURE = CORE + "Diagnostics/LeakCapture.cs"
SERVER = CORE + "Ipc/ControlServer.cs"
PROTOCOL = CORE + "Ipc/ControlProtocol.cs"
HOST = APP + "Hosting/ControlService.cs"
RUNNER = APP + "Hosting/LeakCheckRunner.cs"
MODEL = APP + "MainViewModel.cs"
PAGE = APP + "Views/UpdatePage.xaml"
EXPORT = APP + "Presentation/DiagnosticsExport.cs"
SERVICE_TESTS = "winclient/WinClient.Tests/LeakCheckServiceTests.cs"
IPC_TESTS = "winclient/WinClient.Tests/LeakCheckIpcTests.cs"
MODEL_TESTS = "winclient/WinClient.UiTests/ViewModelLeakCheckTests.cs"
ALLOWED = {PLAN, SERVICE, FORMATTER, CAPTURE, SERVER, PROTOCOL, HOST, RUNNER, MODEL, PAGE, EXPORT,
           SERVICE_TESTS, IPC_TESTS, MODEL_TESTS}

NODE_MISSING = 'public const string NodeMissing = "未找到隧道内核的连接，请先连接，或用 --node 指定节点地址";'
HOST_LINE = "var server = new ControlServer(runtime, desired, updates, version, leakCheck: ServiceLeakChecker.CreateProduction());"
# 每个文件:改动前的行里,只有含这些片段的行许改;别的行要按原顺序原样留着(只许加行)。
CHANGED = {
    FORMATTER: (),
    PAGE: (),
    CAPTURE: ("const string NodeMissing",),
    PROTOCOL: ("public sealed record ControlResponse(",),
    HOST: ("var server = new ControlServer(",),
    EXPORT: ("public sealed record UiDiagnostics(", '["update_message"] = '),
    SERVER: ("public sealed class ControlServer(", "TimeSpan? idleTimeout = null)", "// 会改变连接状态的指令",
             "private static readonly HashSet<string> TrustedOnlyOps"),
    MODEL: ("var ui = new UiDiagnostics(",),
}
# 文件里必须有的片段(定稿的字一字不差)。
NEEDED = {
    PLAN: ["public static class LeakCheckPlan",
           "public static LeakCheckOptions Build(int seconds, string? node, string outputDirectory, bool keepCapture)",
           "public static string? NodeFromKernelConfig(string path)", "ReachProbe.MainTargetFrom(",
           "AppScopeResolver.Resolve(", "new RoutingSettingsStore().Read()", '"leakcheck"', '"config.json"'],
    SERVICE: ["public interface ILeakChecker", "Task<string> RunAsync(CancellationToken token);",
              "public sealed class ServiceLeakChecker(", "public const int Seconds = 120;",
              "LeakReportFormatter.UiText(", "LeakReportFormatter.Json(",
              "public static ServiceLeakChecker CreateProduction()",
              "LeakCheckPlan.NodeFromKernelConfig(LeakCheckPlan.KernelConfigPath)", "LeakCheckPlan.Build"],
    FORMATTER: ["public static string UiText(LeakCheckOptions options, LeakCheckResult result, string? reportPath, DateTime startedAt)",
                'public const string NodeMissingUi = "没找到节点地址，请先连接再检测。";', "LeakCapture.NodeMissing",
                '"无法检测："', "发现可疑流量：", '"未发现可疑流量。"', "未发现可疑流量。名单外程序有 ", " 条直连，按设计直连。",
                "抓到 ", " 个包，没能解析 ", "检测于 ", "yyyy-MM-dd HH:mm", "，抓包 ", '"报告："', "另有 ", " 条，见报告。"],
    CAPTURE: [NODE_MISSING],
    PROTOCOL: ["string? Diagnostics = null, string? LeakCheck = null);"],
    HOST: [HOST_LINE],
    EXPORT: ["string UpdateMessage, string? LeakCheck = null);", '["leak_check"]', "DiagnosticsRedactor.Redact(ui.LeakCheck)",
             '["update_message"] = DiagnosticsRedactor.Redact(ui.UpdateMessage),'],
    SERVER: ["ILeakChecker? leakCheck = null)", '"read_diagnostics", "leak_check"];',
             'public const string LeakCheckBusyError = "泄漏检测正在进行，请等它结束。";',
             'public const string LeakCheckFailedError = "泄漏检测没有完成，请稍后再试。";',
             "private readonly SemaphoreSlim leakChecks = new(1, 1);"],
    RUNNER: ["LeakCheckPlan.Build(seconds, node, outDir, keep)", '"请以管理员身份运行"',
             "开始泄漏检测,抓包 {seconds} 秒,请在此期间正常使用电脑……", "LeakReportFormatter.WriteSummary(Console.Out, options, result, outDir);"],
    MODEL: ['public const string LeakCheckNeedsConnection = "连接后才能检测。";',
            'public const string LeakCheckFailedMessage = "泄漏检测没有完成，请检查后台服务后再试。";',
            'public const string LeakCheckInterruptedMessage = "检测期间连接断开过，这次结果不作数。请连接后重新检测。";',
            "public ICommand LeakCheckCommand { get; }", "public bool IsLeakCheckRunning { get; private set; }",
            'public string LeakCheckMessage { get; private set; } = "";',
            "internal Func<CancellationToken, Task<ControlResponse>> SendLeakCheck { get; set; }",
            "LeakCheckCommand = new AsyncCommand(RunLeakCheckAsync, () => CanLeakCheck);",
            "Notify(nameof(CanLeakCheck)); Notify(nameof(LeakCheckDisabledReason));"],
    PAGE: ['<TextBlock Text="泄漏检测" FontWeight="Bold" Margin="0,24,0,8"/>',
           'Text="查 2 分钟，看网卡上有没有不经节点、直接发往外网的流量。期间照常用电脑，不要断开。"',
           '<Button Content="开始检测" Command="{Binding LeakCheckCommand}" HorizontalAlignment="Left" Margin="0,12,0,0"/>',
           'Text="{Binding LeakCheckDisabledReason}" Style="{DynamicResource Yc.Hint}" Visibility="{Binding LeakCheckDisabledReason, Converter={x:Static t:VisibilityConverter.Instance}}"',
           'Visibility="{Binding IsLeakCheckRunning, Converter={x:Static t:VisibilityConverter.Instance}}"',
           'Text="正在检测，约 2 分钟。"',
           'Text="{Binding LeakCheckMessage}"', 'Visibility="{Binding LeakCheckMessage, Converter={x:Static t:VisibilityConverter.Instance}}"'],
}
# 方法正文里必须有的、不许有的。
MEMBERS = {
    MODEL: {
        "internal async Task RunLeakCheckAsync()": (
            ["!CanLeakCheck", "SendLeakCheck(lifetime.Token)", "LeakCheckFailedMessage", "lastLeakCheck", "OnUiAsync(",
             "leakCheckInterrupted", "LeakCheckInterruptedMessage"],
            ["RunAsync(", "IsBusy", "client.SendAsync", "client!.SendAsync", "Update(snapshot"]),
        "private void Refresh()": (
            ["Notify(nameof(CanLeakCheck)); Notify(nameof(LeakCheckDisabledReason));",
             "if (IsLeakCheckRunning && !ShouldDisconnect) leakCheckInterrupted = true;"], []),
        "private static async Task<ControlResponse> SendLeakCheckOverPipeAsync(CancellationToken token)": (
            ["new NamedPipeClientStream(", "ControlService.PipeName", "PipePeer.VerifyServer(pipe, UpdatePlanner.DefaultAppRoot)",
             'SendAsync("leak_check"', "new ControlClient(pipe)"],
            ["subscribe"]),
        "public Task ExportDiagnosticsAsync(string path)": (["lastLeakCheck"], []),
    },
    EXPORT: {"private static JsonObject BuildUi(UiDiagnostics ui)": (['["leak_check"]', "DiagnosticsRedactor.Redact(ui.LeakCheck)"], [])},
    SERVICE: {"public async Task<string> RunAsync(CancellationToken token)": (
        ["plan(Seconds, node(), ", '"leak-report.json"', "capture(options, token)", "report = null"], ["Console."])},
}
# 这些方法的正文一个字不能变(和改动前逐字比)。
UNTOUCHED = {
    RUNNER: ["private static bool ParseArguments(", "private static void BindConsole()"],
    FORMATTER: ["public static string Json(", "public static void WriteSummary("],
    MODEL: ["private async Task RunAsync(Func<Task> action)", "private async Task InitializeCoreAsync()",
            "private async Task MainActionAsync()", "private async Task SendAsync(string op,"],
}
# 整个文件里不许出现的片段。
BANNED = {
    RUNNER: ["ScopePatterns(", "LoadAuth("],
    SERVICE: ["ProcessStartInfo", "Process.Start"],
    PLAN: ["ProcessStartInfo", "Process.Start", "Console."],
    MODEL: ["Process.Start"],
}
NEW_TESTS = {
    SERVICE_TESTS: {
        "UiTextCleanPutsConclusionFirst": ['"未发现可疑流量。\\n抓到 1234 个包，没能解析 2 个。\\n检测于 2026-11-28 21:03，抓包 120 秒。\\n报告："'],
        "UiTextSuspiciousListsProgramFileNames": ['"发现可疑流量：2 条，共 52 个包。"', '"TCP 74.125.250.129:443 chrome.exe ×40"',
                                                  '"UDP 192.168.1.1:53 未知程序 ×12"', "DoesNotContain("],
        "UiTextCapsFlowsAtTwenty": ['"另有 5 条，见报告。"'],
        "UiTextAppsModeTagsFlows": ['" [名单程序]"', '" [名单外程序(按设计直连)]"', '"发现可疑流量：1 条，共 7 个包。"',
                                    "未发现可疑流量。名单外程序有 1 条直连，按设计直连。"],
        "UiTextUnableShowsReason": ['"无法检测：" + LeakReportFormatter.NodeMissingUi', "LeakCapture.NodeMissing", '"无法检测：抓包文件格式不正确"'],
        "ServiceCheckerPassesNodeFromConfigAndWritesReport": ["new ServiceLeakChecker(", "ServiceLeakChecker.Seconds", '"leak-report.json"',
                                                              '"20261128-210305"', '"203.0.113.9"', "KeepCapture"],
        "ServiceCheckerKeepsTextWhenReportCannotBeWritten": ["new ServiceLeakChecker(", "IOException", 'DoesNotContain("报告："'],
        "NodeFromKernelConfigReadsMainOutboundIpv4": ["LeakCheckPlan.NodeFromKernelConfig(", '"203.0.113.9"', "Assert.Null("],
    },
    IPC_TESTS: {
        "LeakCheckReturnsTextFromChecker": ['"leak_check"', "response.LeakCheck", "leakCheck: "],
        "LeakCheckIsTrustedOnly": ['"leak_check"', "callerTrusted: false", "ControlServer.UntrustedCallerError", "Calls"],
        "LeakCheckUnsupportedWithoutChecker": ['"leak_check"', '"不支持的指令"'],
        "SecondLeakCheckIsRejectedAndCommandsStayFree": ['"leak_check"', "ControlServer.LeakCheckBusyError", '"connect"', "Entered", "Calls"],
        "LeakCheckFailureHidesExceptionText": ['"leak_check"', "ControlServer.LeakCheckFailedError", "IOException", "DoesNotContain("],
    },
    MODEL_TESTS: {
        "LeakCheckDisabledUntilConnected": ["MainViewModel.LeakCheckNeedsConnection", "CanLeakCheck", "LeakCheckCommand.CanExecute(null)",
                                            "ConnectionState.Connected", "ConnectionState.Disconnected"],
        "LeakCheckRunsWithoutOccupyingConnectButton": ["TaskCompletionSource<ControlResponse>", "IsLeakCheckRunning", "model.IsBusy",
                                                       "CanUseConnection", "RunLeakCheckAsync()", "LeakCheck: "],
        "LeakCheckInterruptedByDisconnectDiscardsResult": ["TaskCompletionSource<ControlResponse>", "ConnectionState.Disconnected",
                                                           "MainViewModel.LeakCheckInterruptedMessage", '["leak_check"]'],
        "LeakCheckFailureShowsFixedMessage": ["IOException", "MainViewModel.LeakCheckFailedMessage"],
        "LeakCheckErrorResponseShowsServerError": ["ControlServer.LeakCheckBusyError", "new ControlResponse(1, false"],
        "ExportIncludesLastLeakCheckRedacted": ['["leak_check"]', "WriteDiagnosticsFile", '"[公网地址]:443"', 'DoesNotContain("8.8.8.8"',
                                                "ExportDiagnosticsAsync("],
        "ExportLeakCheckIsNullBeforeAnyRun": ['["leak_check"]', "Assert.Null(", "ExportDiagnosticsAsync("],
    },
}
SKIPS = r"\bSkip\s*=|\bAssert\.Skip\w*\s*\(|\bSkip\.If\w*\s*\(|\bSkippable(?:Fact|Theory)\b"
REAL_WAITS = r"\bTask\.Delay\s*\(|\bThread\.Sleep\s*\("


def text(path):
    file = ROOT / path
    return file.read_text(encoding="utf-8").replace("\r\n", "\n") if file.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    try:
        return git("show", f"{base()}:{path}").replace("\r\n", "\n")
    except subprocess.CalledProcessError:
        return ""


def member(source, signature):
    """取一个方法从签名到正文结束的全文(花括号正文或 => 表达式到分号);找不到返回空串。"""
    start = source.find(signature)
    if start < 0:
        return ""
    brace, arrow = source.find("{", start), source.find("=>", start)
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                # => 写法的方法(如 ExportDiagnosticsAsync)正文在第一个花括号之后还有 ");",一并带上。
                tail = source.find(";", end) if 0 <= arrow < brace else -1
                return source[start:tail + 1] if 0 <= tail <= end + 2 else source[start:end]
    return ""


def dropped(new, old, changed):
    """改动前的每一行(点名许改的除外)都要按原顺序留在新文件里;返回第一处被改或被删的行。"""
    rows = iter(new.splitlines())
    for line in old.splitlines():
        if any(mark in line for mark in changed):
            continue
        if not any(row == line for row in rows):
            return line.strip()[:70] or "(空行)"
    return None


def leak_branch(server):
    execute = member(server, "private async Task<ControlResponse> ExecuteAsync(")
    start, end = execute.find('if (request.Op == "leak_check")'), execute.find("await commands.WaitAsync(token)")
    return execute[start:end] if 0 <= start < end else None


def shape_problems(new, old):
    """new、old:路径 → 全文。old 里新文件为空串。"""
    bad = []
    for path, changed in CHANGED.items():
        if not old[path]:
            bad.append(f"检查脚本读不到改动前的 {path},请交 blocked 告诉派单方")
            continue
        for mark in changed:
            if sum(mark in line for line in old[path].splitlines()) != 1:
                bad.append(f"检查脚本在改动前的 {path} 里找不到唯一的一行「{mark}」,请交 blocked 告诉派单方")
        line = dropped(new[path], old[path], changed)
        if line is not None:
            bad.append(f"{path} 只许加行,这一行被改了或删了:{line}")
    for path, tokens in NEEDED.items():
        if not new[path]:
            bad.append(f"缺文件 {path}")
            continue
        for token in tokens:
            if token not in new[path]:
                bad.append(f"{path} 缺这一段或写法与契约不一致:{token[:80]}")
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

    if len(new[CAPTURE].splitlines()) != len(old[CAPTURE].splitlines()):
        bad.append("LeakCapture.cs 只许把 NodeMissing 那一行的 private 改成 public,别的不动")
    extra = len(new[HOST].splitlines()) - len(old[HOST].splitlines())
    if extra not in (0, 1) or (extra == 1 and "using WinClient.Core.Diagnostics;" not in new[HOST]):
        bad.append("ControlService.cs 只许改创建 ControlServer 的那一行,最多再加一行 using WinClient.Core.Diagnostics;")
    branch = leak_branch(new[SERVER])
    if branch is None:
        bad.append('ControlServer.ExecuteAsync 里 leak_check 那一段要放在 await commands.WaitAsync(token) 之前(不进指令信号量)')
    else:
        for token in ("leakCheck is null", "leakChecks.Wait(0)", "LeakCheckBusyError", "leakCheck.RunAsync(token)",
                      "LeakCheckFailedError", "leakChecks.Release()", "LeakCheck: "):
            if token not in branch:
                bad.append(f"ControlServer 里 leak_check 那一段没有 {token}")
        for token in ("facade.", "desired.", "commands.", "ex.Message", "leakChecks.WaitAsync"):
            if token in branch:
                bad.append(f"ControlServer 里 leak_check 那一段不许出现 {token}")
    can = [line for line in new[MODEL].splitlines() if "public bool CanLeakCheck =>" in line]
    if len(can) != 1 or not all(token in can[0] for token in ("CanUseConnection", "ShouldDisconnect", "!IsLeakCheckRunning")):
        bad.append("MainViewModel 要有一行 public bool CanLeakCheck => CanUseConnection && ShouldDisconnect && !IsLeakCheckRunning;")
    page = new[PAGE]
    spots = [page.find(mark) for mark in ("{Binding DiagnosticsMessage}", 'Text="泄漏检测"', "{Binding LeakCheckMessage}", "IsUpdateIndicatorVisible")]
    if min(spots) < 0 or spots != sorted(spots):
        bad.append("UpdatePage.xaml 里「泄漏检测」这一段要放在导出诊断的结果那行之后、更新进行中那一行之前")
    if new[MODEL].count("PipePeer.VerifyServer(") != 2:
        bad.append("MainViewModel 里 PipePeer.VerifyServer( 要正好出现两次(主连接一次,检测用的第二条连接一次)")
    return bad


def tests_problems(new):
    bad = []
    for path, cases in NEW_TESTS.items():
        source = new[path]
        if not source:
            bad.append(f"缺测试文件 {path}")
            continue
        for name, tokens in cases.items():
            body = member(source, f" {name}(")
            if not re.search(rf"\[Fact\]\s*\n\s*public (?:async Task|void) {name}\(", source) or not body:
                bad.append(f"{path} 缺用例 {name}(要带 [Fact])")
                continue
            bad += [f"用例 {name} 里没有契约要求的 {token}" for token in tokens if token not in body]
            if body.count("Assert.") < 2:
                bad.append(f"用例 {name} 的断言太少")
        if re.search(SKIPS, source):
            bad.append(f"{path} 里不许跳过")
        if re.search(REAL_WAITS, source):
            bad.append(f"{path} 里不许真的等时间(Task.Delay / Thread.Sleep);用 TaskCompletionSource 控制先后")
    if '[Collection("界面线程")]' not in new[MODEL_TESTS]:
        bad.append('ViewModelLeakCheckTests.cs 要标 [Collection("界面线程")]')
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
