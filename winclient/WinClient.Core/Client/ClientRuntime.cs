using System.Runtime.Versioning;
using WinClient.Core.Auth;
using WinClient.Core.Firewall;
using WinClient.Core.Process;
using WinClient.Core.Storage;

namespace WinClient.Core.Client;

[SupportedOSPlatform("windows")]
public sealed class ClientRuntime : IDisposable
{
    private readonly HttpClient? http;
    private readonly KillSwitchApplier firewall;
    public ClientController Controller { get; }
    private ClientRuntime(ClientController controller, KillSwitchApplier firewall, HttpClient? http)
    { Controller = controller; this.firewall = firewall; this.http = http; }

    public static async Task<ClientRuntime> CreateAsync()
    {
        var firewall = new KillSwitchApplier(Path.Combine(ClientSettings.DataDirectory, "run"));
        await firewall.RecoverAsync(); // Recovery precedes even reading server.json.
        var settings = ClientSettings.Load();
        HttpClient? http = null;
        try
        {
            AuthApiClient? auth = null;
            if (settings is not null)
            {
                http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
                { BaseAddress = new Uri(settings.ServerUrl), Timeout = TimeSpan.FromSeconds(15) };
                auth = new AuthApiClient(http);
            }
            var program = settings?.SingBoxPath ?? Path.Combine(ClientSettings.DataDirectory, "sing-box.exe");
            var transport = new TunnelTransport(new SingBoxProcessManager(program, ClientSettings.ProductName));
            var controller = new ClientController(auth, new DpapiCredentialStore(ClientSettings.ProductName), firewall,
                transport, program, new DeviceInfo { Platform = "windows", Name = Environment.MachineName, Fingerprint = ClientSettings.GetDeviceFingerprint() });
            return new(controller, firewall, http);
        }
        catch { http?.Dispose(); throw; }
    }

    /// <summary>Only the firewall audit was added to the diagnostic placeholder by the third dispatch decision.</summary>
    public void ExportFirewallAudit(string destination)
    {
        if (!File.Exists(firewall.AuditPath)) throw new InvalidOperationException("尚无防火墙审计记录，请完成一次连接后再导出。");
        File.Copy(firewall.AuditPath, destination, overwrite: true);
    }
    public void Dispose() { Controller.Dispose(); http?.Dispose(); }
}
