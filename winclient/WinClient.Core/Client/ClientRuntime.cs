using System.Runtime.Versioning;
using WinClient.Core.Auth;
using WinClient.Core.Firewall;
using WinClient.Core.Process;
using WinClient.Core.Storage;
using WinClient.Core.Logging;
using WinClient.Core.Pairing;

namespace WinClient.Core.Client;

[SupportedOSPlatform("windows")]
public sealed class ClientRuntime : IDisposable
{
    private HttpClient? http;
    private readonly KillSwitchApplier firewall;
    private readonly PairingStore pairingStore;
    private readonly RedactingLog log;
    public ClientController Controller { get; }
    private ClientRuntime(ClientController controller, KillSwitchApplier firewall, HttpClient? http, PairingStore pairingStore, RedactingLog log)
    { Controller = controller; this.firewall = firewall; this.http = http; this.pairingStore = pairingStore; this.log = log; }

    public static async Task<ClientRuntime> CreateAsync()
    {
        var firewall = new KillSwitchApplier(Path.Combine(ClientSettings.DataDirectory, "run"));
        await firewall.RecoverAsync(); // Recovery precedes even reading server.json.
        var pairingStore = new PairingStore();
        var log = new RedactingLog(new RollingFileLog(Path.Combine(ClientSettings.DataDirectory, "run", "sing-box.log")));
        var settings = ClientSettings.Load();
        HttpClient? http = null;
        try
        {
            var source = SelectSessionSource(pairingStore, () =>
            {
                if (settings is null) return null;
                http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
                { BaseAddress = new Uri(settings.ServerUrl), Timeout = TimeSpan.FromSeconds(15) };
                return new AuthServerSessionSource(new AuthApiClient(http, log), new DpapiCredentialStore(ClientSettings.ProductName));
            }, log);
            var program = settings?.SingBoxPath ?? Path.Combine(ClientSettings.DataDirectory, "sing-box.exe");
            var transport = new TunnelTransport(new SingBoxProcessManager(program, ClientSettings.ProductName, logger: log));
            var controller = new ClientController(source, firewall,
                transport, program, new DeviceInfo { Platform = "windows", Name = Environment.MachineName, Fingerprint = ClientSettings.GetDeviceFingerprint() });
            return new(controller, firewall, http, pairingStore, log);
        }
        catch { http?.Dispose(); throw; }
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
        }, $"已导入配对文件：{pairing.DisplayName}，点击连接");
    }

    public Task ClearPairingAsync() => Controller.ChangeSessionSourceAsync(() =>
    {
        // Validate the fallback first, leaving the imported pairing intact on failure.
        var settings = ClientSettings.Load();
        HttpClient? nextHttp = settings is null ? null : new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        { BaseAddress = new Uri(settings.ServerUrl), Timeout = TimeSpan.FromSeconds(15) };
        try { pairingStore.Clear(); }
        catch { nextHttp?.Dispose(); throw; }
        http?.Dispose(); http = nextHttp;
        return http is null ? null : new AuthServerSessionSource(new AuthApiClient(http, log), new DpapiCredentialStore(ClientSettings.ProductName));
    }, "已清除配对文件；可导入新的配对文件，或在已配置服务器时使用邀请码。");

    /// <summary>Only the firewall audit was added to the diagnostic placeholder by the third dispatch decision.</summary>
    public void ExportFirewallAudit(string destination)
    {
        if (!File.Exists(firewall.AuditPath)) throw new InvalidOperationException("尚无防火墙审计记录，请完成一次连接后再导出。");
        File.Copy(firewall.AuditPath, destination, overwrite: true);
    }
    public void Dispose() { Controller.Dispose(); http?.Dispose(); }
}
