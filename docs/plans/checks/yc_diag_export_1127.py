"""导出诊断单 yc-diag-export-always-writes-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
REDACTOR = WIN / "WinClient.Core/Diagnostics/DiagnosticsRedactor.cs"
LOG_TAIL = WIN / "WinClient.Core/Diagnostics/LogTail.cs"
PROBE = WIN / "WinClient.Core/Diagnostics/FirewallStateProbe.cs"
COLLECTOR = WIN / "WinClient.Core/Diagnostics/DiagnosticsCollector.cs"
PROTOCOL = WIN / "WinClient.Core/Ipc/ControlProtocol.cs"
EXPORT = WIN / "WinClient.App/Presentation/DiagnosticsExport.cs"
VIEW_MODEL = WIN / "WinClient.App/MainViewModel.cs"
WINDOW = WIN / "WinClient.App/MainWindow.xaml.cs"
UPDATE_PAGE = WIN / "WinClient.App/Views/UpdatePage.xaml"
T_REDACTOR = WIN / "WinClient.Tests/DiagnosticsRedactorTests.cs"
T_LOG_TAIL = WIN / "WinClient.Tests/LogTailTests.cs"
T_PROBE = WIN / "WinClient.Tests/FirewallStateProbeTests.cs"
T_COLLECTOR = WIN / "WinClient.Tests/DiagnosticsCollectorTests.cs"
T_PROTOCOL = WIN / "WinClient.Tests/DiagnosticsProtocolTests.cs"
T_EXPORT = WIN / "WinClient.UiTests/DiagnosticsExportTests.cs"
T_VIEW_MODEL = WIN / "WinClient.UiTests/ViewModelDiagnosticsTests.cs"
DOC_ENV = ROOT / "docs/winclient/环境一致性说明.md"
DOC_UI = ROOT / "docs/winclient/界面说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Diagnostics/DiagnosticsRedactor.cs",
    "winclient/WinClient.Core/Diagnostics/LogTail.cs",
    "winclient/WinClient.Core/Diagnostics/FirewallStateProbe.cs",
    "winclient/WinClient.Core/Diagnostics/DiagnosticsCollector.cs",
    "winclient/WinClient.Core/Ipc/ControlProtocol.cs",
    "winclient/WinClient.App/Presentation/DiagnosticsExport.cs",
    "winclient/WinClient.App/MainViewModel.cs",
    "winclient/WinClient.App/MainWindow.xaml.cs",
    "winclient/WinClient.App/Views/UpdatePage.xaml",
    "winclient/WinClient.Tests/DiagnosticsRedactorTests.cs",
    "winclient/WinClient.Tests/LogTailTests.cs",
    "winclient/WinClient.Tests/FirewallStateProbeTests.cs",
    "winclient/WinClient.Tests/DiagnosticsCollectorTests.cs",
    "winclient/WinClient.Tests/DiagnosticsProtocolTests.cs",
    "winclient/WinClient.UiTests/DiagnosticsExportTests.cs",
    "winclient/WinClient.UiTests/ViewModelDiagnosticsTests.cs",
    "docs/winclient/环境一致性说明.md",
    "docs/winclient/界面说明.md",
}
RESPONSE = ("public sealed record ControlResponse(long? Id, bool Ok, string? Error = null, ControlSnapshot? Snapshot = null, "
            "string? Audit = null, string? SelfCheck = null, string? Diagnostics = null);")
PAGE_LINE = ('<TextBlock Text="{Binding DiagnosticsMessage}" Style="{DynamicResource Yc.Hint}" AutomationProperties.LiveSetting="Polite" '
             'Visibility="{Binding DiagnosticsMessage, Converter={x:Static t:VisibilityConverter.Instance}}"/>')
SCRIPT_LINES = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "function Read-Profiles($store) { try { @(Get-NetFirewallProfile -PolicyStore $store | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; default_outbound = [string]$_.DefaultOutboundAction; default_inbound = [string]$_.DefaultInboundAction } }) } catch { @() } }",
    "$service = try { [string](Get-Service -Name MpsSvc).Status } catch { 'unknown' }",
    "$own = try { @(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'YuanC-KS-*' -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; action = [string]$_.Action; direction = [string]$_.Direction } }) } catch { @() }",
    "$outbound = try { @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -ErrorAction SilentlyContinue) } catch { @() }",
    "$result = [ordered]@{ service = $service; profiles_local = @(Read-Profiles 'PersistentStore'); profiles_effective = @(Read-Profiles 'ActiveStore'); own_rules = @($own); outbound_rules_total = $outbound.Count; outbound_rules_enabled = @($outbound | Where-Object { [string]$_.Enabled -eq 'True' }).Count; outbound_allow_enabled = @($outbound | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Allow' }).Count }",
    "ConvertTo-Json -InputObject $result -Depth 5 -Compress",
]
WRITES_SYSTEM = ["Set-Net", "Enable-Net", "Disable-Net", "New-Net", "Remove-Net", "netsh", "Restart-Service", "Stop-Service", "Start-Service"]
EXPORT_TEXTS = [
    'public const string ServiceUnreachable = "后台服务没有连上。";',
    'public const string ServiceTimedOut = "后台服务超过时限没有返回诊断。";',
    'public const string ServiceEmpty = "后台服务没有返回诊断。";',
    'public const string ServiceInvalid = "后台服务返回的诊断不是有效的 JSON。";',
    'public const string WriteFailed = "导出失败：文件没能写到所选位置，请换一个位置再试。";',
    'public const string ExportedPrefix = "已导出：";',
    'public const string UiOnlyNote = "（后台服务的记录没有取到，文件里只有界面这边的信息）";',
    "澳洲出口客户端-诊断-",
    "yyyyMMdd-HHmmss",
]
TESTS = {
    T_REDACTOR: ["PublicIpv4IsMaskedAndPrivateKept", "PublicIpv6IsMaskedAndLocalKept", "TimestampsAndVersionsAreNotTouched",
                 "UserDirectoryIsMaskedInPlainAndJsonEscapedPaths", "LabelledSecretsAndBearerAreHidden", "NullAndEmptyBecomeEmpty",
                 "RedactStructuredKeepsJsonValid"],
    T_LOG_TAIL: ["MissingFileIsReportedWithoutThrowing", "ReturnsLastLinesAndMarksTruncated", "PrependsRotatedFileWhenCurrentIsShort",
                 "LinesAreRedactedAndOverlongLinesCut", "ReadsWhileAnotherHandleIsAppending", "OversizeFileDropsPartialFirstLine"],
    T_PROBE: ["ScriptIsReadOnly", "RunUsesHiddenWindowStartInfo", "ReturnsLastJsonLine", "NonZeroExitOrBadJsonReportsFailed",
              "TimeoutReportsTimedOut", "ExternalCancelStillThrows"],
    T_COLLECTOR: ["CollectsAllSectionsAsValidJson", "SnapshotOmitsExitIpAndKeepsOnlyAppFileNames", "FailingSourceIsRecordedAndOthersSurvive",
                  "FirewallResultIsEmbeddedOrErrorCarried", "StateFileIsSummarizedNotCopied", "BrokenStateFileIsReported",
                  "MarkersReflectFiles", "LogsAreTrimmedToFitBudget", "OversizeAuditIsOmittedAndNamed",
                  "AuditAndSelfCheckAreRedactedBeforeEmbedding", "InvalidAuditJsonIsDroppedWithError", "AdapterAddressesAreRedacted",
                  "CancellationPropagates"],
    T_PROTOCOL: ["ResponseCarriesDiagnosticsField", "OldResponseWithoutFieldDecodesToNull"],
    T_EXPORT: ["DefaultFileNameCarriesTimestamp", "WritesFileEvenWithoutService", "UsesServiceDiagnosticsWhenAvailable",
               "FallsBackToAuditAndSelfCheckWhenUnsupported", "WritesFileWhenNothingWasEverRecorded", "PipeFailureStillWritesFile",
               "SlowServiceTimesOutAndStillWritesFile", "InvalidServiceJsonIsDroppedWithError", "WriteFailureIsReportedNotThrown",
               "UiSectionOmitsExitIpAndRedactsMessage", "ComposeKeepsKeyOrder"],
    T_VIEW_MODEL: ["ExportWritesFileAndShowsResultOnUpdatePageProperty", "ExportFailureShowsReasonAndDoesNotReveal",
                   "SuggestedFileNameHasPrefixAndJsonExtension", "DiagnosticsMessageStartsEmpty"],
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
    redactor = text(REDACTOR)
    need(redactor, ["namespace WinClient.Core.Diagnostics", "public static class DiagnosticsRedactor",
                    'public const string PublicAddressMark = "[公网地址]";', 'public const string UserMark = "[用户]";',
                    'public const string TimedOutMark = "[脱敏超时，内容已隐藏]";',
                    "public static string RedactStructured(string? text)", "public static string Redact(string? text)",
                    "PublicAddress.IsPublic(", "RedactingLog", "RegexMatchTimeoutException",
                    "(?<![0-9.])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![0-9.])",
                    "(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"], "DiagnosticsRedactor.cs", bad)
    tail = text(LOG_TAIL)
    need(tail, ["public sealed record LogTailResult(string Name, bool Missing, long Bytes, bool Truncated, IReadOnlyList<string> Lines, string? Error = null);",
                "public static class LogTail", "public const int MaxLineChars = 2000;", "public const int MaxReadBytes = 512 * 1024;",
                "public static LogTailResult Read(string directory, string name, int maxLines)",
                "FileShare.ReadWrite | FileShare.Delete", "DiagnosticsRedactor.Redact(", "读取失败"], "LogTail.cs", bad)
    probe = text(PROBE)
    need(probe, ["public sealed record FirewallStateResult(string? Json, string? Error);", "public static class FirewallStateProbe",
                 "public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);",
                 'public const string TimedOut = "系统防火墙现状没有读到：超过时限没有返回。";',
                 'public const string Failed = "系统防火墙现状没有读到：查询命令没有成功。";',
                 "public const string Script =",
                 "public static async Task<FirewallStateResult> RunAsync(ICommandRunner runner, TimeSpan? timeout = null, CancellationToken token = default)",
                 "KillSwitchApplier.CreateStartInfo(Script)", *SCRIPT_LINES], "FirewallStateProbe.cs", bad)
    for word in WRITES_SYSTEM:
        if word in probe:
            bad.append("FirewallStateProbe.cs 只许读系统,不许出现 " + word)
    if "new CommandRunner(" in probe:
        bad.append("FirewallStateProbe.cs 的执行器必须由调用方传入")
    collector = text(COLLECTOR)
    need(collector, ["public sealed class DiagnosticsSources", "public required string RunDirectory { get; init; }",
                     "public required Func<ClientSnapshot> Snapshot { get; init; }", 'public string Version { get; init; } = "";',
                     "public bool TestBuild { get; init; }", "public Func<bool?>? Desired { get; init; }",
                     "public Func<IReadOnlyList<string>>? WfpFilterNames { get; init; }",
                     "public Func<IReadOnlyList<AdapterInfo>?>? Adapters { get; init; }",
                     "public Func<CancellationToken, Task<FirewallStateResult>>? Firewall { get; init; }",
                     "public Func<string?>? Audit { get; init; }", "public Func<string?>? SelfCheck { get; init; }",
                     "public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;",
                     "public static class DiagnosticsCollector", "public const int MaxEncodedBytes = 900 * 1024;",
                     '["service.log", "connect.log", "sing-box.log", "update.log", "killswitch-recovery.log"]',
                     "internal static readonly int[] LineBudgets = [400, 200, 100, 40, 10, 0];",
                     "public static async Task<string> CollectAsync(DiagnosticsSources sources, CancellationToken token = default)",
                     "internal static int EncodedBytes(string diagnostics)", "ControlProtocol.Encode(", "UnsafeRelaxedJsonEscaping",
                     "LogTail.Read(", "DiagnosticsRedactor.RedactStructured(", "DiagnosticsRedactor.Redact(",
                     "killswitch-state.json", "firewall-audit.json", "wfp-off", "route-off", "不是有效的 JSON",
                     *[f'"{key}"' for key in ("schema", "collected_at", "version", "test_build", "system", "snapshot", "desired",
                                               "killswitch", "wfp_filters", "adapters", "firewall", "firewall_error", "logs",
                                               "firewall_audit", "self_check", "omitted", "errors", "uptime_minutes",
                                               "utc_offset_minutes", "routing_apps", "summary", "audit_file", "wfp_off", "route_off")]],
         "DiagnosticsCollector.cs", bad)
    for word in ("ExitIp", "exit_ip", "Process.Start", "new CommandRunner("):
        if word in collector:
            bad.append("DiagnosticsCollector.cs 不许出现 " + word)
    protocol = text(PROTOCOL)
    need(protocol, [RESPONSE, "public const int MaxLineBytes = 1024 * 1024;", "PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower",
                    "public sealed record ControlRequest(long Id, string Op, string? Code = null, string? PairingJson = null, bool? Enabled = null,"],
         "ControlProtocol.cs", bad)
    export = text(EXPORT)
    need(export, ["namespace WinClient.App.Presentation",
                  "public sealed record UiDiagnostics(string UiVersion, string ServiceVersion, string Availability, ClientSnapshot Snapshot, string UpdateStage, string UpdateMessage);",
                  "public sealed record DiagnosticsExportResult(bool Written, bool ServiceIncluded, string Message);",
                  "public static class DiagnosticsExport", *EXPORT_TEXTS,
                  "public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(45);",
                  "public static string DefaultFileName(DateTimeOffset localNow)",
                  "public static string Compose(UiDiagnostics ui, DateTimeOffset now, string? service, string? serviceError, string? audit, string? selfCheck)",
                  "public static async Task<DiagnosticsExportResult> RunAsync(",
                  "public static bool RevealInExplorer(string path)",
                  '"read_diagnostics"', '"read_audit"', '"read_selfcheck"', "explorer.exe", "/select,", "CreateNoWindow = true",
                  "UseShellExecute = false", "System.Diagnostics.Process", "UnsafeRelaxedJsonEscaping", "WriteIndented = true",
                  "new UTF8Encoding(false)", "DiagnosticsRedactor.RedactStructured(", "DiagnosticsRedactor.Redact(",
                  *[f'"{key}"' for key in ("schema", "exported_at", "ui", "service", "service_error", "firewall_audit", "self_check",
                                            "service_version", "service_availability", "update_stage", "update_message", "routing_apps")]],
         "DiagnosticsExport.cs", bad)
    for word in ("ExitIp", "exit_ip"):
        if word in export:
            bad.append("DiagnosticsExport.cs 不许写出口地址:" + word)
    model = text(VIEW_MODEL)
    need(model, ['public string DiagnosticsMessage { get; private set; } = "";',
                 "internal Func<string, bool> RevealFile { get; set; } = DiagnosticsExport.RevealInExplorer;",
                 "internal Func<string, string, CancellationToken, Task>? WriteDiagnosticsFile { get; set; }",
                 "public string SuggestedDiagnosticsFileName => DiagnosticsExport.DefaultFileName(NowProvider().ToLocalTime());",
                 "public Task ExportDiagnosticsAsync(string path)", "DiagnosticsExport.RunAsync(", "new UiDiagnostics(",
                 "Notify(nameof(DiagnosticsMessage))", "RevealFile(path)",
                 # 下面是不许动的既有成员。
                 "public void ApplyPreview(ControlSnapshot snapshot, ServiceAvailability availability, bool connectionUsable = false)",
                 "public async Task LoadSelfCheckAsync()", "操作未完成，请检查后台服务或联系管理员。",
                 "无法连接后台服务,请重启电脑或联系管理员", "private async Task RunAsync(Func<Task> action)"], "MainViewModel.cs", bad)
    for word in ("ExportAuditAsync", "尚无可导出的诊断记录", "已导出诊断(防火墙审计 + 环境自检)。"):
        if word in model:
            bad.append("MainViewModel.cs 还留着旧的导出写法:" + word)
    window = text(WINDOW)
    need(window, ["model.SuggestedDiagnosticsFileName", "model.ExportDiagnosticsAsync(dialog.FileName)",
                  "Environment.SpecialFolder.DesktopDirectory", "(_, e) => e.CanExecute = !model.IsBusy"], "MainWindow.xaml.cs", bad)
    if "ExportAuditAsync" in window or "诊断报告.json" in window:
        bad.append("MainWindow.xaml.cs 还在用旧的导出方法或旧文件名")
    page = text(UPDATE_PAGE)
    need(page, [PAGE_LINE, "把防火墙审计和环境自检报告合成一个文件(不含出口 IP),发给管理员排查。",
                '<TextBlock Text="正在处理,请稍候再导出诊断。"', 'Content="导出诊断…"'], "UpdatePage.xaml", bad)
    if page.count("DiagnosticsMessage") != 2:
        bad.append("UpdatePage.xaml 里 DiagnosticsMessage 只许出现在新加的那一行(两处绑定)")
    busy = page.find('<TextBlock Text="正在处理,请稍候再导出诊断。"')
    added = page.find(PAGE_LINE)
    if busy < 0 or added < busy:
        bad.append("UpdatePage.xaml 新加的那一行要紧跟在「正在处理,请稍候再导出诊断。」后面")
    fail(bad)


def tests():
    bad = []
    for path, names in TESTS.items():
        body = text(path)
        if not body:
            bad.append("缺测试文件 " + path.name)
            continue
        for name in names:
            if " " + name + "(" not in body:
                bad.append(f"{path.name} 缺用例 {name}")
        for word in ("new CommandRunner(", "Process.Start(", "RevealInExplorer(", "ClientSettings.DataDirectory",
                     "WfpEngine.CreateProduction", "new KillSwitchApplier("):
            if word in body:
                bad.append(f"{path.name} 不许碰真系统:{word}")
    need(text(T_REDACTOR), ["8.8.8.8", "1.1.1.1", "192.168.1.52", "198.18.255.1", "2404:6800:4006:80a::200e", "fe80::1c2d:3e4f:5a6b:7c8d",
                            "2001:db8::1", "2026-11-28T01:02:03.1234567+00:00 版本 0.1.2 系统 10.0.19045", "alice", "[用户]", "[公网地址]",
                            "[已隐藏]", "abc123", "xyz789"], "DiagnosticsRedactorTests", bad)
    need(text(T_LOG_TAIL), [".1", "FileShare.ReadWrite", "LogTail.MaxReadBytes", "…"], "LogTailTests", bad)
    need(text(T_PROBE), ["FirewallStateProbe.Failed", "FirewallStateProbe.TimedOut", "CreateNoWindow", "UseShellExecute",
                         "OperationCanceledException", '"Set-"', '"Enable-"', '"Disable-"', '"netsh"'], "FirewallStateProbeTests", bad)
    need(text(T_COLLECTOR), ["DiagnosticsCollector.EncodedBytes(", "DiagnosticsCollector.MaxEncodedBytes", "disabledRules_count",
                             "profiles_count", "auth_keys", "不是有效的 JSON", "InvalidOperationException", "[公网地址]/24",
                             "192.168.1.5/24", "chrome.exe", "wfp-off", "omitted", "OperationCanceledException"],
         "DiagnosticsCollectorTests", bad)
    need(text(T_PROTOCOL), ["diagnostics", "ControlProtocol.DecodeResponse("], "DiagnosticsProtocolTests", bad)
    need(text(T_EXPORT), ["澳洲出口客户端-诊断-20261128-090507.json", "DiagnosticsExport.UiOnlyNote", "不支持的指令",
                          "read_diagnostics", "read_audit", "read_selfcheck", "后台服务没有连上。", "后台服务超过时限没有返回诊断。",
                          "后台服务返回的诊断不是有效的 JSON。", "导出失败：文件没能写到所选位置，请换一个位置再试。",
                          "UnauthorizedAccessException", "8.8.8.8", "alice", "exported_at"], "DiagnosticsExportTests", bad)
    need(text(T_VIEW_MODEL), ['[Collection("界面线程")]', "UiThreadFixture", "ui.Invoke(", "WriteDiagnosticsFile", "RevealFile",
                              "已导出：", "导出失败：文件没能写到所选位置，请换一个位置再试。", "nameof(MainViewModel.DiagnosticsMessage)",
                              "澳洲出口客户端-诊断-", ".json"], "ViewModelDiagnosticsTests", bad)
    fail(bad)


def docs():
    bad = []
    env = text(DOC_ENV)
    need(env, ["read_diagnostics", "read_audit", "read_selfcheck", "澳洲出口客户端-诊断-", "桌面", "任何情况下都会写出文件",
               "service_error", "导出按钮下方", "[公网地址]", "[用户]", "[已隐藏]", "不含出口 IP", "exported_at",
               "点击导出诊断，在文件里找到 firewall_audit 与 self_check(后台支持 read_diagnostics 时在 service 段里，否则在顶层)；",
               "导出诊断(真机待验证)", "## 在浏览器里复核", "环境自检真机待验证（本单未执行）："], "环境一致性说明.md", bad)
    for stale in ("保存为 `诊断报告.json`", "尚无可导出的诊断记录", "已导出诊断(防火墙审计 + 环境自检)。"):
        if stale in env:
            bad.append("环境一致性说明.md 还留着旧说法:" + stale)
    ui = text(DOC_UI)
    need(ui, ["导出结果显示在本页导出按钮下方；任何情况下都会写出文件，内容已脱敏，不含出口 IP。",
              "配对文件和程序选择对话框的行为保持原有语义。", "| 账号与配对 |", "| 代理范围 |"], "界面说明.md", bad)
    if "诊断导出的行为保持原有语义" in ui:
        bad.append("界面说明.md 还写着诊断导出保持原有语义")
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
