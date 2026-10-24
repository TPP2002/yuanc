using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Firewall;
using WinClient.Core.Process;
using WinClient.Core.Storage;
using WinClient.Core.Logging;
using WinClient.Core.Pairing;
using WinClient.Core.Kernel;
using WinClient.Core.Hosting;
using WinClient.Core.EnvironmentSupport;

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
        string? storeRoot, DataProtectionScope scope)
    { Controller = controller; this.firewall = firewall; this.http = http; this.pairingStore = pairingStore; this.log = log; this.storeRoot = storeRoot; this.scope = scope; }

    public static async Task<ClientRuntime> CreateAsync(IKernelInstaller installer, string? storeRoot = null,
        DataProtectionScope scope = DataProtectionScope.CurrentUser, bool keepProtection = false)
    {
        var firewall = new KillSwitchApplier(Path.Combine(ClientSettings.DataDirectory, "run"));
        if (!keepProtection)
        {
            try { await firewall.RecoverAsync(); } // 恢复路径仍先于读取服务器配置。
            catch (InvalidOperationException)
            {
                // 启动恢复失败由 Controller.InitializeAsync 再试并进入需人工处理，服务不得因此退出。
            }
        }
        var pairingStore = new PairingStore(root: storeRoot, scope: scope);
        var log = new RedactingLog(new RollingFileLog(Path.Combine(ClientSettings.DataDirectory, "run", "sing-box.log")));
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
            var transport = new TunnelTransport(new SingBoxProcessManager(program, ClientSettings.ProductName, logger: log));
            var controller = new ClientController(source, firewall,
                transport, program, new DeviceInfo { Platform = "windows", Name = Environment.MachineName, Fingerprint = ClientSettings.GetDeviceFingerprint(storeRoot, scope) },
                authEndpoint: settings?.AuthEndpoint, exitProbe: new HttpExitProbe(),
                environment: new EnvironmentApplier(Path.Combine(ClientSettings.DataDirectory, "run")),
                environmentSettings: new EnvironmentSettingsStore(), ipv6Probe: new SocketIpv6Probe(),
                reportSink: report => WriteSelfCheck(Path.Combine(ClientSettings.DataDirectory, "run", "selfcheck.json"), report),
                routingSettings: new RoutingSettingsStore(), serviceProcessPath: Environment.ProcessPath, adapterProbe: new SystemAdapterProbe(),
                browserProbe: new SystemBrowserProcessProbe());
            return new(controller, firewall, http, pairingStore, log, storeRoot, scope);
        }
        catch { http?.Dispose(); throw; }
    }

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
