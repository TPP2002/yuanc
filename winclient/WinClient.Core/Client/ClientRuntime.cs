using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Diagnostics;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using WinClient.Core.Process;
using WinClient.Core.Storage;
using WinClient.Core.Logging;
using WinClient.Core.Pairing;
using WinClient.Core.Kernel;
using WinClient.Core.Hosting;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Ipc;

namespace WinClient.Core.Client;

[SupportedOSPlatform("windows")]
public sealed class ClientRuntime : IClientFacade, IDisposable
{
    private HttpClient? http;
    private readonly KillSwitchApplier firewall;
    private readonly PairingStore pairingStore;
    private readonly RedactingLog log;
    private readonly string? storeRoot;
    private readonly DataProtectionScope scope;
    // 过滤层引擎与测试包标记存下来供诊断采集复用；不改变启动与连接行为。
    private readonly IWfpEngine? wfp;
    private readonly bool testBuild;
    /// <summary>防火墙现状与路由 DNS 现状探测各自的时限；超时只让对应诊断段留空。</summary>
    internal static readonly TimeSpan FirewallProbeTimeout = TimeSpan.FromSeconds(10);
    internal static readonly TimeSpan NetworkProbeTimeout = TimeSpan.FromSeconds(10);
    public ClientController Controller { get; }
    public ClientSnapshot Snapshot => Controller.Snapshot;
    public string? RecoveryWarning => firewall.LastRecoveryWarning;
    public event Action<ClientSnapshot>? Changed { add => Controller.Changed += value; remove => Controller.Changed -= value; }
    public Task ConnectAsync() => Controller.ConnectAsync();
    public Task DisconnectAsync() => Controller.DisconnectAsync();
    public Task SetRoutingAsync(string mode, IReadOnlyList<string> apps) => Controller.SetRoutingAsync(mode, apps);
    public Task SetEnvironmentEnabledAsync(bool enabled) => Controller.SetEnvironmentEnabledAsync(enabled);
    public Task RestoreEnvironmentAsync() => Controller.ForceRestoreEnvironmentAsync();
    public Task RedeemAsync(string code) => Controller.RedeemAsync(code);
    public string? ReadAudit() => File.Exists(firewall.AuditPath) ? File.ReadAllText(firewall.AuditPath) : null;
    public string? ReadSelfCheck()
    {
        var path = Path.Combine(ClientSettings.DataDirectory, "run", "selfcheck.json");
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }
    private ClientRuntime(ClientController controller, KillSwitchApplier firewall, HttpClient? http, PairingStore pairingStore, RedactingLog log,
        string? storeRoot, DataProtectionScope scope, IWfpEngine? wfp, bool testBuild)
    { Controller = controller; this.firewall = firewall; this.http = http; this.pairingStore = pairingStore; this.log = log; this.storeRoot = storeRoot; this.scope = scope; this.wfp = wfp; this.testBuild = testBuild; }

    public static async Task<ClientRuntime> CreateAsync(IKernelInstaller installer, string? storeRoot = null,
        DataProtectionScope scope = DataProtectionScope.CurrentUser, bool keepProtection = false, bool testBuild = false)
    {
        var log = new RedactingLog(new RollingFileLog(Path.Combine(ClientSettings.DataDirectory, "run", "sing-box.log")));
        // 连接记录单写一份,只放本单定义的三类行;节点地址、出口地址与令牌不进这份记录。
        var connectLog = new RedactingLog(new RollingFileLog(Path.Combine(ClientSettings.DataDirectory, "run", "connect.log")));
        // 后台服务启动时先清一次上次残留的连接内核；这一层失败不让服务起不来，连接时 Start 还会再清一次并报错。
        var kernelDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ClientSettings.ProductName, "bin");
        try
        {
            new StrayKernelSweeper().Sweep(Path.Combine(kernelDirectory, "sing-box.exe"), kernelDirectory, log.Write);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            // 服务不能因为清残留失败而起不来；保持保护与不保持两条路都一样。
        }
        var wfp = WfpEngine.CreateProduction();
        var firewall = new KillSwitchApplier(Path.Combine(ClientSettings.DataDirectory, "run"), wfp: wfp, routes: new RouteGuard(), log: connectLog.Write);
        if (!keepProtection)
        {
            try { await firewall.RecoverAsync(); } // 恢复路径仍先于读取服务器配置。
            catch (InvalidOperationException)
            {
                // 启动恢复失败由 Controller.InitializeAsync 再试并进入需人工处理，服务不得因此退出。
            }
        }
        var pairingStore = new PairingStore(root: storeRoot, scope: scope);
        var settings = ClientSettings.Load(ownerIsTrusted: DataDirectorySecurity.IsTrustedOwner);
        HttpClient? http = null;
        try
        {
            var source = SelectSessionSource(pairingStore, () =>
            {
                if (settings is null) return null;
                http = settings.CreateAuthHttpClient();
                return new AuthServerSessionSource(new AuthApiClient(http, log), new DpapiCredentialStore(ClientSettings.ProductName, root: storeRoot, scope: scope));
            }, log);
            var program = settings?.SingBoxPath ?? installer.Ensure();
            var transport = new TunnelTransport(new SingBoxProcessManager(program, ClientSettings.ProductName, logger: log)) { KernelLog = testBuild };
            var nic = new NicGuard(Path.Combine(ClientSettings.DataDirectory, "run"), new SystemAdapterProbe());
            var controller = new ClientController(source, GuardFor(firewall, testBuild),
                transport, program, new DeviceInfo { Platform = "windows", Name = Environment.MachineName, Fingerprint = ClientSettings.GetDeviceFingerprint(storeRoot, scope) },
                authEndpoint: settings?.AuthEndpoint, exitProbe: new HttpExitProbe(),
                environment: new EnvironmentApplier(Path.Combine(ClientSettings.DataDirectory, "run")),
                environmentSettings: new EnvironmentSettingsStore(), ipv6Probe: new SocketIpv6Probe(),
                reportSink: report => WriteSelfCheck(Path.Combine(ClientSettings.DataDirectory, "run", "selfcheck.json"), report),
                routingSettings: new RoutingSettingsStore(), serviceProcessPath: Environment.ProcessPath, adapterProbe: new SystemAdapterProbe(),
                browserProbe: new SystemBrowserProcessProbe(),
                nicGuard: testBuild ? new DisabledNicGuard(nic) : nic,
                reaper: testBuild ? null : new ConnectionReaper(new SystemTcpTable()),
                proxyProbe: new RegistryProxySettingsProbe(),
                scopeResolver: path => AppScopeResolver.Resolve(path, AppScopeResolver.SystemFolders(), new SystemAppScopeFileSystem()))
                { Journal = connectLog.Write, TestBuild = testBuild };
            return new(controller, firewall, http, pairingStore, log, storeRoot, scope, wfp, testBuild);
        }
        catch { http?.Dispose(); throw; }
    }

    /// <summary>测试包交给控制器的断网保护换成不执行的外壳;正式包原样返回同一个对象。</summary>
    internal static IKillSwitch GuardFor(IKillSwitch real, bool testBuild) => testBuild ? new DisabledKillSwitch(real) : real;

    /// <summary>诊断采集的来源装配;测试直接注入命令、网卡与过滤层替身,生产用真实实现。</summary>
    internal static DiagnosticsSources DiagnosticsSourcesFor(string runDirectory, Func<ClientSnapshot> snapshot, bool testBuild,
        IWfpEngine? wfp, ICommandRunner runner, IAdapterProbe adapters, Func<string?> audit, Func<string?> selfCheck) => new()
        {
            RunDirectory = runDirectory,
            Snapshot = snapshot,
            Version = ControlSnapshot.CurrentVersion,
            TestBuild = testBuild,
            Desired = () => new DesiredStateStore(runDirectory).Read(),
            WfpFilterNames = wfp is null ? null : () => wfp.ListFilterNames(),
            Adapters = () => adapters.Snapshot(),
            Firewall = token => FirewallStateProbe.RunAsync(runner, FirewallProbeTimeout, token),
            Network = token => NetworkStateProbe.RunAsync(runner, NetworkProbeTimeout, token),
            Audit = audit,
            SelfCheck = selfCheck
        };

    /// <summary>界面经管道读诊断;采集库自己兜住各段异常,拿不到结果才交给服务端回「不支持的指令」。</summary>
    public Task<string?> ReadDiagnosticsAsync(CancellationToken token = default) =>
        CollectDiagnosticsAsync(DiagnosticsSourcesFor(Path.Combine(ClientSettings.DataDirectory, "run"), () => Controller.Snapshot,
            testBuild, wfp, new CommandRunner(), new SystemAdapterProbe(), ReadAudit, ReadSelfCheck), token);

    private static async Task<string?> CollectDiagnosticsAsync(DiagnosticsSources sources, CancellationToken token) =>
        await DiagnosticsCollector.CollectAsync(sources, token).ConfigureAwait(false);

    internal static void WriteSelfCheck(string path, EnvironmentReport report)
    {
        var temporary = path + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            try
            {
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, new { report.CheckedAt, report.Summary, report.Items },
                        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
                    stream.Flush(true);
                }
                File.Move(temporary, path, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException or System.Security.SecurityException)
        { } // 诊断落盘失败不改变连接状态，也不记录报告或异常正文。
    }

    public static ISessionSource? SelectSessionSource(PairingStore store, Func<ISessionSource?> serverSource, RedactingLog? log = null)
    {
        var pairing = store.Load();
        return pairing is not null ? new PairingSessionSource(pairing, log) : serverSource();
    }

    public Task ImportPairingAsync(string json)
    {
        var pairing = PairingFile.Parse(json);
        return Controller.ChangeSessionSourceAsync(() =>
        {
            pairingStore.Save(pairing);
            http?.Dispose(); http = null;
            return new PairingSessionSource(pairing, log);
        }, PairingImportMessage(pairing));
    }

    public static string PairingImportMessage(PairingFile pairing) =>
        $"已导入配对文件：{pairing.DisplayName}，点击连接" + (pairing.Warning is null ? "" : "。" + pairing.Warning);

    public Task ClearPairingAsync() => Controller.ChangeSessionSourceAsync(() =>
    {
        // Validate the fallback first, leaving the imported pairing intact on failure.
        var settings = ClientSettings.Load(ownerIsTrusted: DataDirectorySecurity.IsTrustedOwner);
        HttpClient? nextHttp = settings is null ? null : settings.CreateAuthHttpClient();
        try { pairingStore.Clear(); }
        catch { nextHttp?.Dispose(); throw; }
        http?.Dispose(); http = nextHttp;
        return http is null ? null : new AuthServerSessionSource(new AuthApiClient(http, log), new DpapiCredentialStore(ClientSettings.ProductName, root: storeRoot, scope: scope));
    }, "已清除配对文件；可导入新的配对文件，或在已配置服务器时使用邀请码。");

    /// <summary>Only the firewall audit was added to the diagnostic placeholder by the third dispatch decision.</summary>
    public void ExportFirewallAudit(string destination)
    {
        if (!File.Exists(firewall.AuditPath)) throw new InvalidOperationException("尚无防火墙审计记录，请完成一次连接后再导出。");
        File.Copy(firewall.AuditPath, destination, overwrite: true);
    }
    public void Dispose() { Controller.Dispose(); http?.Dispose(); }
}
