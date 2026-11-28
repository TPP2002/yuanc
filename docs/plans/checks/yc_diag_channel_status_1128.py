"""诊断补通道状态单 yc-diag-channel-status-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
RUNTIME = WIN / "WinClient.Core/Client/ClientRuntime.cs"
TRANSPORT = WIN / "WinClient.Core/Client/TunnelTransport.cs"
COLLECTOR = WIN / "WinClient.Core/Diagnostics/DiagnosticsCollector.cs"
REDACTOR = WIN / "WinClient.Core/Diagnostics/DiagnosticsRedactor.cs"
NETWORK = WIN / "WinClient.Core/Diagnostics/NetworkStateProbe.cs"
CHANNEL = WIN / "WinClient.Core/Diagnostics/KernelChannelProbe.cs"
REACH = WIN / "WinClient.Core/Diagnostics/ReachProbe.cs"
RENDERER = WIN / "WinClient.Core/Pairing/LocalConfigRenderer.cs"
SELFCHECK = WIN / "WinClient.Core/Environment/EnvironmentSelfCheck.cs"
T_NEW = WIN / "WinClient.Tests/DiagnosticsChannelTests.cs"
DOC_EXPORT = ROOT / "docs/winclient/诊断导出说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Client/ClientRuntime.cs",
    "winclient/WinClient.Core/Client/TunnelTransport.cs",
    "winclient/WinClient.Core/Diagnostics/DiagnosticsCollector.cs",
    "winclient/WinClient.Core/Diagnostics/DiagnosticsRedactor.cs",
    "winclient/WinClient.Core/Diagnostics/NetworkStateProbe.cs",
    "winclient/WinClient.Core/Diagnostics/KernelChannelProbe.cs",
    "winclient/WinClient.Core/Diagnostics/ReachProbe.cs",
    "winclient/WinClient.Tests/DiagnosticsChannelTests.cs",
    "docs/winclient/诊断导出说明.md",
}
TEST_NAMES = [
    "StatusEndpointOffKeepsConfigurationUnchanged", "StatusEndpointOnAddsLoopbackStatusApi",
    "StatusEndpointCreatePicksLoopbackPortAndRandomSecret", "MainTargetReadsMainOutbound",
    "TransportOpensStatusApiOnlyWhenKernelLogOn", "ChannelProbeReportsSelectedAndDelays",
    "ChannelProbeReturnsFixedErrors", "ReachProbeWithoutTargetReturnsFixedError", "ReachProbeReportsRefused",
    "ReachProbeReportsHandshakeCutByPeer", "ReachProbeReportsHandshakeTimeout", "ReachProbeReportsIssuerOnSuccess",
    "CollectorEmbedsChannelSectionsAndRedacts", "CollectorOmitsChannelSectionsWhenNotWired",
    "CollectorStartsProbesTogether", "KernelLogLinesLoseColorCodes", "NetworkScriptListsSecurityProducts",
    "SourcesCarryChannelProbesOnlyWhenGiven",
]
TEST_WORDS = [
    "TunnelTransport.RenderConfiguration(", "new KernelStatusEndpoint(23456, \"abc\")", "127.0.0.1:23456", "cache_file",
    "KernelStatusEndpoint.Create()", "ReachProbe.MainTargetFrom(", "203.0.113.9", "www.example.com",
    "StatusEndpoint", "MainTarget", "ConfigPath", "external_controller",
    "KernelChannelProbe.RunAsync(", "KernelChannelProbe.NotRunning", "KernelChannelProbe.Failed", "KernelChannelProbe.TimedOut",
    "KernelChannelProbe.TestUrl", "Bearer", "timeout=3000", "last_delay_ms", "last_test_at", "test_ok", "test_delay_ms",
    "test_status", "HttpRequestException",
    "ReachProbe.RunAsync(", "ReachProbe.NoTarget", "TcpListener", "refused", "timeout", "closed", "reset",
    "YuanC-Test-CA", "cert_issuer", "cert_errors", "tls_protocol", "tcp_ms",
    "channels_error", "node_reach_error", "ipv6_reach_error", "[公网地址]", "InvalidOperationException",
    "ERROR[0000] dial [域名]", "DiagnosticsRedactor.StripColorCodes(",
    "NetworkStateProbe.Script", "root/SecurityCenter2", "AntiVirusProduct", "FirewallProduct", "security_products",
    "ClientRuntime.DiagnosticsSourcesFor(",
]
# 路由与 DNS 现状脚本的十行原文;第 8 行是新插入的,第 9 行是改过的,其余与上一张单相同。
PROBE_LINES = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "$lo = [System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex",
    "function Read-Routes($store) { try { @(Get-NetRoute -PolicyStore $store -ErrorAction SilentlyContinue | Where-Object { [string]$_.DestinationPrefix -match '/[0-2]$' } | ForEach-Object { [ordered]@{ prefix = [string]$_.DestinationPrefix; next_hop = [string]$_.NextHop; alias = [string]$_.InterfaceAlias; index = [int]$_.InterfaceIndex; metric = [int]$_.RouteMetric; loopback = ([int]$_.InterfaceIndex -eq $lo) } }) } catch { @() } }",
    "$interfaces = try { @(Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; index = [int]$_.ifIndex; family = [string]$_.AddressFamily; metric = [int]$_.InterfaceMetric; state = [string]$_.ConnectionState; dhcp = [string]$_.Dhcp } }) } catch { @() }",
    "$dns = try { @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { @($_.ServerAddresses).Count -gt 0 } | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; family = $(if ([int]$_.AddressFamily -eq 23) { 'IPv6' } else { 'IPv4' }); servers = @($_.ServerAddresses | ForEach-Object { [string]$_ }) } }) } catch { @() }",
    "$kernel = try { @(Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ id = [int]$_.Id; started = try { $_.StartTime.ToUniversalTime().ToString('o') } catch { '' }; path = try { [string]$_.Path } catch { '' } } }) } catch { @() }",
    "function Read-Security($class) { try { @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $class -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ kind = $class; name = [string]$_.displayName; state = [string]$_.productState } }) } catch { @() } }",
    "$result = [ordered]@{ loopback_index = $lo; routes_active = @(Read-Routes 'ActiveStore'); routes_persistent = @(Read-Routes 'PersistentStore'); interfaces = @($interfaces); dns = @($dns); kernel_processes = @($kernel); security_products = @(@(Read-Security 'AntiVirusProduct') + @(Read-Security 'FirewallProduct')) }",
    "ConvertTo-Json -InputObject $result -Depth 5 -Compress",
]
OLD_RESULT_LINE = "kernel_processes = @($kernel) }"
SECTION_KEYS = ["channels", "channels_error", "node_reach", "node_reach_error", "ipv6_reach", "ipv6_reach_error"]


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
    channel = text(CHANNEL)
    if not channel:
        bad.append("缺文件 KernelChannelProbe.cs")
    else:
        need(channel, ["namespace WinClient.Core.Diagnostics;",
                       "public sealed record KernelStatusEndpoint(int Port, string Secret)",
                       "public static KernelStatusEndpoint Create()", "IPAddress.Loopback", "RandomNumberGenerator.GetBytes(16)",
                       "public override string ToString()",
                       "public sealed record ChannelStateResult(string? Json, string? Error);",
                       "public static class KernelChannelProbe",
                       "public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(6);",
                       "public const int DelayTimeoutMs = 3000;",
                       'public const string TestUrl = "https://www.gstatic.com/generate_204";',
                       'public const string NotRunning = "通道状态没有读到：连接内核没有在运行。";',
                       'public const string TimedOut = "通道状态没有读到：超过时限没有返回。";',
                       'public const string Failed = "通道状态没有读到：内核的状态口没有正常应答。";',
                       "RunAsync(KernelStatusEndpoint? endpoint, HttpMessageHandler? handler = null, TimeSpan? timeout = null, CancellationToken token = default)",
                       "UseProxy = false", "Bearer", "/proxies", "/delay?url=", "Uri.EscapeDataString(TestUrl)",
                       '"selected"', '"last_delay_ms"', '"last_test_at"', '"test_ok"', '"test_delay_ms"', '"test_status"'],
             "KernelChannelProbe.cs", bad)
        for word in ("Process.Start(", "ProcessStartInfo", "using System.Diagnostics;"):
            if word in channel:
                bad.append("KernelChannelProbe.cs 不许起子进程或引入 System.Diagnostics:" + word)
    reach = text(REACH)
    if not reach:
        bad.append("缺文件 ReachProbe.cs")
    else:
        need(reach, ["namespace WinClient.Core.Diagnostics;",
                     "public sealed record ReachTarget(string Host, int Port, string ServerName);",
                     "public sealed record ReachResult(string? Json, string? Error);",
                     "public static class ReachProbe",
                     "public static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(4);",
                     'public static readonly ReachTarget Ipv6Target = new("2606:4700:4700::1111", 443, "one.one.one.one");',
                     'public const string NoTarget = "直连握手探测没有做：后台服务这次启动以来还没有连接过，没有可测的目标。";',
                     "public static ReachTarget? MainTargetFrom(JsonElement configuration)",
                     "RunAsync(ReachTarget? target, bool bindPhysical, TimeSpan? stepTimeout = null, CancellationToken token = default)",
                     "DefaultRouteBinding.Pick(", "DefaultRouteBinding.ReadSystem()", "(SocketOptionName)31", "SslStream",
                     "RemoteCertificateValidationCallback", "SslPolicyErrors", "Issuer",
                     '"bound"', '"tcp"', '"tcp_ms"', '"tls"', '"tls_ms"', '"tls_protocol"', '"cert_errors"', '"cert_issuer"',
                     '"refused"', '"reset"', '"unreachable"', '"timeout"', '"closed"', '"failed"', '"ok"'],
             "ReachProbe.cs", bad)
        for word in ("Process.Start(", "ProcessStartInfo", "using System.Diagnostics;", ".WriteAsync(", ".SendAsync(", ".Send("):
            if word in reach:
                bad.append("ReachProbe.cs 只握手不传数据、不起子进程,不许出现 " + word)
    transport = text(TRANSPORT)
    need(transport, ["public KernelStatusEndpoint? StatusEndpoint", "public ReachTarget? MainTarget",
                     "public static JsonElement RenderConfiguration(JsonElement configuration, bool kernelLog, KernelStatusEndpoint? status)",
                     "RenderConfiguration(configuration, kernelLog, null)",
                     "manager.Start(RenderConfiguration(configuration, KernelLog, status))",
                     "KernelStatusEndpoint.Create()", "ReachProbe.MainTargetFrom(configuration)",
                     '"experimental"', '"clash_api"', '"external_controller"', '"secret"',
                     # 下面是不许动的既有写法。
                     "public bool KernelLog { get; init; }",
                     "public static JsonElement RenderConfiguration(JsonElement configuration, bool kernelLog)",
                     "public static JsonElement RenderConfiguration(JsonElement configuration) => RenderConfiguration(configuration, false);",
                     '"disabled"', '"level"', '"warn"', '"timestamp"', 'tuns[0]["strict_route"] = true;', 'tuns[0]["auto_route"] = true;',
                     "连接内核尚未建立虚拟网卡。", "连接内核在启动期间退出。", "manager.StopAndSweep();",
                     "if (settled >= SettlePolls) return;"], "TunnelTransport.cs", bad)
    redactor = text(REDACTOR)
    need(redactor, ["public static string StripColorCodes(string? text)", r"\x1B\[[0-9;]*[A-Za-z]",
                    # 下面是不许动的既有写法。
                    'public const string DomainMark = "[域名]";', "public static string MaskDomains(string? text)",
                    'public const string PublicAddressMark = "[公网地址]";', "public static string Redact(string? text)",
                    "public static string RedactStructured(string? text)"], "DiagnosticsRedactor.cs", bad)
    collector = text(COLLECTOR)
    need(collector, ["public Func<CancellationToken, Task<ChannelStateResult>>? Channels { get; init; }",
                     "public Func<CancellationToken, Task<ReachResult>>? NodeReach { get; init; }",
                     "public Func<CancellationToken, Task<ReachResult>>? Ipv6Reach { get; init; }",
                     "sources.Channels", "sources.NodeReach", "sources.Ipv6Reach",
                     "DiagnosticsRedactor.StripColorCodes(", "DiagnosticsRedactor.MaskDomains(",
                     # 下面是不许动的既有写法。
                     "public Func<CancellationToken, Task<NetworkStateResult>>? Network { get; init; }",
                     "public const int MaxEncodedBytes = 900 * 1024;", '["network"]', '["network_error"]', '"prefix"',
                     '["service.log", "connect.log", "sing-box.log", "update.log", "killswitch-recovery.log"]',
                     "internal static readonly int[] LineBudgets = [400, 200, 100, 40, 10, 0];"], "DiagnosticsCollector.cs", bad)
    for key in SECTION_KEYS:
        if f'"{key}"' not in collector:
            bad.append(f"DiagnosticsCollector.cs 缺键 {key}")
    network = text(NETWORK)
    need(network, ["public sealed record NetworkStateResult(string? Json, string? Error);", "public static class NetworkStateProbe",
                   "public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);",
                   'public const string TimedOut = "路由与 DNS 现状没有读到：超过时限没有返回。";',
                   'public const string Failed = "路由与 DNS 现状没有读到：查询命令没有成功。";',
                   "Task<NetworkStateResult> RunAsync(ICommandRunner runner, TimeSpan? timeout = null, CancellationToken token = default)",
                   "KillSwitchApplier.CreateStartInfo(Script)", "安全软件"], "NetworkStateProbe.cs", bad)
    for number, line in enumerate(PROBE_LINES, 1):
        if line not in network:
            bad.append(f"NetworkStateProbe.cs 的脚本第 {number} 行与契约原文不一致")
    if OLD_RESULT_LINE in network:
        bad.append("NetworkStateProbe.cs 还留着没带 security_products 的旧 $result 行")
    for word in ("Set-", "New-", "Remove-", "Enable-", "Disable-", "Stop-", "Restart-", "Add-", "Clear-", "Start-Process"):
        if word in network:
            bad.append("NetworkStateProbe.cs 的脚本只许读,不许出现 " + word)
    runtime = text(RUNTIME)
    need(runtime, ["Func<CancellationToken, Task<ChannelStateResult>>? channels = null",
                   "Func<CancellationToken, Task<ReachResult>>? nodeReach = null",
                   "Func<CancellationToken, Task<ReachResult>>? ipv6Reach = null",
                   "KernelChannelProbe.RunAsync(", ".StatusEndpoint", "ReachProbe.RunAsync(", ".MainTarget", "ReachProbe.Ipv6Target",
                   # 下面是不许动的既有写法。
                   "internal static DiagnosticsSources DiagnosticsSourcesFor(",
                   "string runDirectory, Func<ClientSnapshot> snapshot, bool testBuild,",
                   "public Task<string?> ReadDiagnosticsAsync(CancellationToken token = default)",
                   "FirewallStateProbe.RunAsync(runner, FirewallProbeTimeout, token)",
                   "NetworkStateProbe.RunAsync(runner, NetworkProbeTimeout, token)", "KernelLog = testBuild",
                   "internal static IKillSwitch GuardFor(IKillSwitch real, bool testBuild) => testBuild ? new DisabledKillSwitch(real) : real;",
                   "nicGuard: testBuild ? new DisabledNicGuard(nic) : nic,",
                   "reaper: testBuild ? null : new ConnectionReaper(new SystemTcpTable()),",
                   "{ Journal = connectLog.Write, TestBuild = testBuild };", "if (!keepProtection)",
                   "ipv6Probe: new SocketIpv6Probe(),",
                   "try { await firewall.RecoverAsync(); }"], "ClientRuntime.cs", bad)
    renderer = text(RENDERER)
    if "log = new { disabled = true }," not in renderer or "clash_api" in renderer or "experimental" in renderer:
        bad.append("LocalConfigRenderer.cs 不许改(正式包配置要与节点样本一致,状态口只由 TunnelTransport 在测试包里加)")
    selfcheck = text(SELFCHECK)
    if 'IPAddress.Parse("2606:4700:4700::1111"), 443' not in selfcheck or "ReachProbe" in selfcheck:
        bad.append("EnvironmentSelfCheck.cs 不许改(自检的判定办法本单不动)")
    fail(bad)


def tests():
    bad = []
    body = text(T_NEW)
    if not body:
        fail(["缺测试文件 DiagnosticsChannelTests.cs"])
    for name in TEST_NAMES:
        if " " + name + "(" not in body:
            bad.append("DiagnosticsChannelTests.cs 缺用例 " + name)
    need(body, TEST_WORDS, "DiagnosticsChannelTests.cs", bad)
    for word in ("new CommandRunner(", "Process.Start(", "ClientSettings.DataDirectory", "WfpEngine.CreateProduction",
                 "new KillSwitchApplier(", "ClientRuntime.CreateAsync(", "new SystemAdapterProbe(", "bindPhysical: true",
                 "ReachProbe.Ipv6Target, ", "new SocketsHttpHandler"):
        if word in body:
            bad.append("DiagnosticsChannelTests.cs 不许碰真系统或连外部地址:" + word)
    fail(bad)


def docs():
    bad = []
    doc = text(DOC_EXPORT)
    if not doc:
        fail(["缺文档 docs/winclient/诊断导出说明.md"])
    need(doc, ["channels", "channels_error", "node_reach", "node_reach_error", "ipv6_reach", "ipv6_reach_error",
               "selected", "last_delay_ms", "last_test_at", "test_ok", "test_delay_ms", "test_status",
               "bound", "tcp_ms", "tls_ms", "tls_protocol", "cert_errors", "cert_issuer",
               "refused", "reset", "unreachable", "timeout", "closed", "failed",
               "security_products", "kind", "颜色码", "clash_api", "127.0.0.1", "只有测试包有", "正式包",
               "三段（只有测试包有）", "真机待验证（本单未执行）",
               # 下面是原文档里不许丢的内容。
               "导出诊断", "澳洲出口客户端-诊断-", "exported_at", "service_error", "firewall_audit", "self_check",
               "collected_at", "test_build", "killswitch", "profiles", "network_error", "routes_active", "routes_persistent",
               "kernel_processes", "9473", "wfp_filters", "adapters", "firewall_error", "omitted", "errors",
               "service.log", "connect.log", "sing-box.log", "update.log", "killswitch-recovery.log",
               "[公网地址]", "[用户]", "[已隐藏]", "[域名]", "不含出口 IP", "read_diagnostics", "warn",
               "连接记录说明.md"], "诊断导出说明.md", bad)
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
