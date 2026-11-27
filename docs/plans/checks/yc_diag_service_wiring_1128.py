"""诊断后台接线单 yc-diag-service-wiring-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
FACADE = WIN / "WinClient.Core/Client/IClientFacade.cs"
RUNTIME = WIN / "WinClient.Core/Client/ClientRuntime.cs"
TRANSPORT = WIN / "WinClient.Core/Client/TunnelTransport.cs"
SERVER = WIN / "WinClient.Core/Ipc/ControlServer.cs"
REDACTOR = WIN / "WinClient.Core/Diagnostics/DiagnosticsRedactor.cs"
COLLECTOR = WIN / "WinClient.Core/Diagnostics/DiagnosticsCollector.cs"
PROBE = WIN / "WinClient.Core/Diagnostics/NetworkStateProbe.cs"
RENDERER = WIN / "WinClient.Core/Pairing/LocalConfigRenderer.cs"
T_WIRING = WIN / "WinClient.Tests/DiagnosticsWiringTests.cs"
DOC_EXPORT = ROOT / "docs/winclient/诊断导出说明.md"
DOC_GUARD = ROOT / "docs/winclient/断网保护加固说明.md"
DOC_ARCH = ROOT / "docs/winclient/架构说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Client/IClientFacade.cs",
    "winclient/WinClient.Core/Client/ClientRuntime.cs",
    "winclient/WinClient.Core/Client/TunnelTransport.cs",
    "winclient/WinClient.Core/Ipc/ControlServer.cs",
    "winclient/WinClient.Core/Diagnostics/DiagnosticsRedactor.cs",
    "winclient/WinClient.Core/Diagnostics/DiagnosticsCollector.cs",
    "winclient/WinClient.Core/Diagnostics/NetworkStateProbe.cs",
    "winclient/WinClient.Tests/DiagnosticsWiringTests.cs",
    "docs/winclient/诊断导出说明.md",
    "docs/winclient/断网保护加固说明.md",
    "docs/winclient/架构说明.md",
}
TEST_NAMES = [
    "OldFacadeWithoutOverrideReturnsNull", "ReadDiagnosticsReturnsFacadeJson", "ReadDiagnosticsIsTrustedOnly",
    "ReadDiagnosticsUnsupportedWhenFacadeReturnsNull", "ReadDiagnosticsOversizeIsRejected",
    "ReadDiagnosticsFailureReturnsFixedError", "ReadDiagnosticsDoesNotWaitForRunningCommand",
    "KernelLogOffKeepsConfigurationUnchanged", "KernelLogOnEnablesWarnLevelOnly", "MaskDomainsHidesHostNamesAndKeepsMarks",
    "CollectorMasksDomainsOnlyInKernelLog", "SourcesCarryVersionTestBuildAndInjectedProbes",
    "StateSummaryKeepsProfileDefaults", "NetworkProbeScriptIsReadOnly", "NetworkProbeReturnsLastJsonLineOrError",
    "CollectorEmbedsNetworkAndKeepsRoutePrefixes",
]
TEST_WORDS = [
    "read_diagnostics", "ControlServer.UntrustedCallerError", "不支持的指令", "诊断内容过大，请联系管理员。",
    "诊断没有取到，请稍后再试。", "IOException", "TunnelTransport.RenderConfiguration(", "GetRawText()", '"warn"',
    "DiagnosticsRedactor.MaskDomains(", "dial tcp www.example.com:443: i/o timeout", "dial tcp [域名]:443: i/o timeout",
    "[公网地址] 与 192.168.1.52 与 10.0.19045", "sing-box.log", "service.log", "ClientRuntime.DiagnosticsSourcesFor(",
    "ControlSnapshot.CurrentVersion", "DesiredStateStore", "CreateNoWindow",
    "killswitch-state.json", "DefaultOutboundAction", "profiles_count", "rules_count",
    "NetworkStateProbe.Script", "NetworkStateProbe.RunAsync(", "NetworkStateProbe.TimedOut", "NetworkStateProbe.Failed",
    "Get-DnsClientServerAddress", "128.0.0.0/1", "114.114.114.114", "network_error",
]
# 路由与 DNS 现状脚本的九行原文;工人要逐字写进 NetworkStateProbe.cs。
PROBE_LINES = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "$lo = [System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex",
    "function Read-Routes($store) { try { @(Get-NetRoute -PolicyStore $store -ErrorAction SilentlyContinue | Where-Object { [string]$_.DestinationPrefix -match '/[0-2]$' } | ForEach-Object { [ordered]@{ prefix = [string]$_.DestinationPrefix; next_hop = [string]$_.NextHop; alias = [string]$_.InterfaceAlias; index = [int]$_.InterfaceIndex; metric = [int]$_.RouteMetric; loopback = ([int]$_.InterfaceIndex -eq $lo) } }) } catch { @() } }",
    "$interfaces = try { @(Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; index = [int]$_.ifIndex; family = [string]$_.AddressFamily; metric = [int]$_.InterfaceMetric; state = [string]$_.ConnectionState; dhcp = [string]$_.Dhcp } }) } catch { @() }",
    "$dns = try { @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { @($_.ServerAddresses).Count -gt 0 } | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; family = $(if ([int]$_.AddressFamily -eq 23) { 'IPv6' } else { 'IPv4' }); servers = @($_.ServerAddresses | ForEach-Object { [string]$_ }) } }) } catch { @() }",
    "$kernel = try { @(Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ id = [int]$_.Id; started = try { $_.StartTime.ToUniversalTime().ToString('o') } catch { '' }; path = try { [string]$_.Path } catch { '' } } }) } catch { @() }",
    "$result = [ordered]@{ loopback_index = $lo; routes_active = @(Read-Routes 'ActiveStore'); routes_persistent = @(Read-Routes 'PersistentStore'); interfaces = @($interfaces); dns = @($dns); kernel_processes = @($kernel) }",
    "ConvertTo-Json -InputObject $result -Depth 5 -Compress",
]
OLD_RECOVERY_TAIL = "界面导出诊断仍只导出原来的防火墙审计文件，不包含这些恢复证据。"
NEW_RECOVERY_TAIL = ("脚本超过时限被中止时也会追加一行（阶段后面写 timeout）。每次防火墙脚本的阶段、退出码、用时与错误摘要另写进 `connect.log`；"
                     "界面导出诊断会带上这几份日志的末尾和 `killswitch-state.json` 的摘要，见[诊断导出说明](诊断导出说明.md)。")
ARCH_NEW_1 = ("诊断按钮导出一个 JSON 文件，含后台服务的日志末尾、系统防火墙与过滤层现状、断网保护恢复记录摘要、防火墙审计与环境自检，"
              "见[诊断导出说明](诊断导出说明.md)。")
ARCH_OLD_1 = "诊断按钮合并导出防火墙审计与环境自检报告；完整诊断包、日志打包等仍是后续功能。"
ARCH_NEW_2 = "仍不实施运行时内核下载、安装向导或 Windows 代码签名。"
ARCH_OLD_2 = "仍不实施完整诊断包、运行时内核下载、安装向导或 Windows 代码签名。"


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
    facade = text(FACADE)
    need(facade, ["Task<string?> ReadDiagnosticsAsync(CancellationToken token = default) => Task.FromResult<string?>(null);",
                  "string? ReadAudit();", "string? ReadSelfCheck();", "Task ConnectAsync();"], "IClientFacade.cs", bad)
    runtime = text(RUNTIME)
    need(runtime, ["log: connectLog.Write", "internal static readonly TimeSpan FirewallProbeTimeout = TimeSpan.FromSeconds(10);",
                   "internal static DiagnosticsSources DiagnosticsSourcesFor(", "string runDirectory, Func<ClientSnapshot> snapshot, bool testBuild,",
                   "IWfpEngine? wfp, ICommandRunner runner, IAdapterProbe adapters,", "Func<string?> audit, Func<string?> selfCheck)",
                   "public Task<string?> ReadDiagnosticsAsync(CancellationToken token = default)",
                   "DiagnosticsCollector.CollectAsync(", "ControlSnapshot.CurrentVersion", "new DesiredStateStore(runDirectory).Read()",
                   "wfp.ListFilterNames()", "adapters.Snapshot()", "FirewallStateProbe.RunAsync(runner, FirewallProbeTimeout, token)",
                   "new CommandRunner()", "new SystemAdapterProbe()", "KernelLog = testBuild",
                   "internal static readonly TimeSpan NetworkProbeTimeout = TimeSpan.FromSeconds(10);",
                   "NetworkStateProbe.RunAsync(runner, NetworkProbeTimeout, token)",
                   # 下面是不许动的既有写法。
                   "internal static IKillSwitch GuardFor(IKillSwitch real, bool testBuild) => testBuild ? new DisabledKillSwitch(real) : real;",
                   "nicGuard: testBuild ? new DisabledNicGuard(nic) : nic,",
                   "reaper: testBuild ? null : new ConnectionReaper(new SystemTcpTable()),",
                   "{ Journal = connectLog.Write, TestBuild = testBuild };", "if (!keepProtection)",
                   "new StrayKernelSweeper().Sweep(Path.Combine(kernelDirectory, \"sing-box.exe\"), kernelDirectory, log.Write);",
                   "try { await firewall.RecoverAsync(); }"], "ClientRuntime.cs", bad)
    if runtime.find('"run", "connect.log"') > runtime.find("new KillSwitchApplier(") >= 0:
        bad.append("ClientRuntime.cs 里连接记录要先于断网保护执行器创建")
    transport = text(TRANSPORT)
    need(transport, ["public bool KernelLog { get; init; }",
                     "public static JsonElement RenderConfiguration(JsonElement configuration, bool kernelLog)",
                     "public static JsonElement RenderConfiguration(JsonElement configuration)",
                     "RenderConfiguration(configuration, false)", "manager.Start(RenderConfiguration(configuration, KernelLog))",
                     '"disabled"', '"level"', '"warn"', '"timestamp"', 'tuns[0]["strict_route"] = true;', 'tuns[0]["auto_route"] = true;',
                     "连接内核尚未建立虚拟网卡。", "manager.StopAndSweep();", "if (settled >= SettlePolls) return;"], "TunnelTransport.cs", bad)
    server = text(SERVER)
    need(server, ['"read_diagnostics"', "private readonly SemaphoreSlim diagnostics = new(1, 1);", "facade.ReadDiagnosticsAsync(token)",
                  "Diagnostics:", '"不支持的指令"', '"诊断内容过大，请联系管理员。"', '"诊断没有取到，请稍后再试。"', "TimeoutException",
                  "diagnostics.Release()",
                  # 下面是不许动的既有写法。
                  'if (request.Op == "status") return new(request.Id, true, Snapshot: Snapshot());',
                  "desired.Write(ShouldStayConnected(facade.Snapshot));", '"审计记录过大，请联系管理员。"', '"自检报告过大，请联系管理员。"',
                  "await commands.WaitAsync(token).ConfigureAwait(false);"], "ControlServer.cs", bad)
    trusted = next((line for line in server.split("\n") if "TrustedOnlyOps =" in line), "")
    if '"read_diagnostics"' not in trusted:
        bad.append("ControlServer.cs 的 TrustedOnlyOps 要加 read_diagnostics")
    wait_at = server.find("await commands.WaitAsync(token)")
    handled_at = server.find('request.Op == "read_diagnostics"')
    if handled_at < 0 or wait_at < 0 or handled_at > wait_at:
        bad.append("ControlServer.cs 的 read_diagnostics 要在等 commands 之前处理(不排在连接指令后面)")
    if 'case "read_diagnostics"' in server:
        bad.append("ControlServer.cs 的 read_diagnostics 不许放进 commands 里面的 switch")
    redactor = text(REDACTOR)
    need(redactor, ['public const string DomainMark = "[域名]";', "public static string MaskDomains(string? text)",
                    r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
                    'public const string PublicAddressMark = "[公网地址]";', "public static string Redact(string? text)",
                    "public static string RedactStructured(string? text)"], "DiagnosticsRedactor.cs", bad)
    collector = text(COLLECTOR)
    need(collector, ["DiagnosticsRedactor.MaskDomains(", '"DefaultOutboundAction"', '"killswitch_state_file"',
                     '"firewall_audit_file"', '"_count"', '["network"]', '["network_error"]', '"prefix"', "sources.Network",
                     "public Func<CancellationToken, Task<NetworkStateResult>>? Network { get; init; }",
                     "public const int MaxEncodedBytes = 900 * 1024;",
                     '["service.log", "connect.log", "sing-box.log", "update.log", "killswitch-recovery.log"]',
                     "internal static readonly int[] LineBudgets = [400, 200, 100, 40, 10, 0];"], "DiagnosticsCollector.cs", bad)
    probe = text(PROBE)
    if not probe:
        bad.append("缺文件 NetworkStateProbe.cs")
    else:
        need(probe, ["public sealed record NetworkStateResult(string? Json, string? Error);", "public static class NetworkStateProbe",
                     "public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);",
                     'public const string TimedOut = "路由与 DNS 现状没有读到：超过时限没有返回。";',
                     'public const string Failed = "路由与 DNS 现状没有读到：查询命令没有成功。";', "public const string Script",
                     "Task<NetworkStateResult> RunAsync(ICommandRunner runner, TimeSpan? timeout = null, CancellationToken token = default)",
                     "KillSwitchApplier.CreateStartInfo(Script)"], "NetworkStateProbe.cs", bad)
        for number, line in enumerate(PROBE_LINES, 1):
            if line not in probe:
                bad.append(f"NetworkStateProbe.cs 的脚本第 {number} 行与契约原文不一致")
        for word in ("Set-", "New-", "Remove-", "Enable-", "Disable-", "Stop-", "Restart-", "Add-", "Clear-", "Start-Process"):
            if word in probe:
                bad.append("NetworkStateProbe.cs 的脚本只许读,不许出现 " + word)
    if "log = new { disabled = true }," not in text(RENDERER):
        bad.append("LocalConfigRenderer.cs 的 log 段不许改(正式包配置要与节点样本一致)")
    fail(bad)


def tests():
    bad = []
    body = text(T_WIRING)
    if not body:
        fail(["缺测试文件 DiagnosticsWiringTests.cs"])
    for name in TEST_NAMES:
        if " " + name + "(" not in body:
            bad.append("DiagnosticsWiringTests.cs 缺用例 " + name)
    need(body, TEST_WORDS, "DiagnosticsWiringTests.cs", bad)
    for word in ("new CommandRunner(", "Process.Start(", "ClientSettings.DataDirectory", "WfpEngine.CreateProduction",
                 "new KillSwitchApplier(", "ClientRuntime.CreateAsync(", "new SystemAdapterProbe("):
        if word in body:
            bad.append("DiagnosticsWiringTests.cs 不许碰真系统:" + word)
    fail(bad)


def docs():
    bad = []
    doc = text(DOC_EXPORT)
    if not doc:
        bad.append("缺文档 docs/winclient/诊断导出说明.md")
    else:
        need(doc, ["导出诊断", "桌面", "澳洲出口客户端-诊断-", "exported_at", "service_error", "firewall_audit", "self_check",
                   "collected_at", "test_build", "killswitch", "profiles", "network", "network_error", "routes_active",
                   "routes_persistent", "interfaces", "dns", "kernel_processes", "9473", "wfp_filters", "adapters", "firewall_error", "omitted", "errors",
                   "service.log", "connect.log", "sing-box.log", "update.log", "killswitch-recovery.log",
                   "[公网地址]", "[用户]", "[已隐藏]", "[域名]", "不含出口 IP", "read_diagnostics", "warn", "测试包", "正式包",
                   "连接记录说明.md", "真机待验证（本单未执行）"], "诊断导出说明.md", bad)
    guard = text(DOC_GUARD)
    need(guard, [NEW_RECOVERY_TAIL, "## 撤销次序与脚本时限", "180 秒", "系统防火墙设置超过时限没有完成，已中止。", "防火墙脚本[",
                 "## 防火墙配置档被关闭或被策略覆盖", "## 首次连接失败自动恢复", "## 测试包(断网保护关闭)"], "断网保护加固说明.md", bad)
    if OLD_RECOVERY_TAIL in guard:
        bad.append("断网保护加固说明.md 还留着「界面导出诊断仍只导出原来的防火墙审计文件」的旧说法")
    if 0 <= guard.find("## 防火墙配置档被关闭或被策略覆盖") < guard.find("## 撤销次序与脚本时限"):
        bad.append("断网保护加固说明.md 的「撤销次序与脚本时限」一节要放在「防火墙配置档被关闭或被策略覆盖」之前")
    arch = text(DOC_ARCH)
    need(arch, [ARCH_NEW_1, ARCH_NEW_2], "架构说明.md", bad)
    for stale in (ARCH_OLD_1, ARCH_OLD_2):
        if stale in arch:
            bad.append("架构说明.md 还留着旧说法:" + stale)
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
