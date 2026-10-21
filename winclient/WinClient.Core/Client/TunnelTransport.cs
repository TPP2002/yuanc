using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Firewall;
using WinClient.Core.Process;

namespace WinClient.Core.Client;

public interface ITunnelTransport : IDisposable
{
    event EventHandler? TunnelDown;
    Task StartAsync(JsonElement configuration, CancellationToken cancellationToken);
    void Stop();
}

public sealed class TunnelTransport : ITunnelTransport
{
    private readonly SingBoxProcessManager manager;
    private readonly Func<bool> ready;
    private bool exited;
    public event EventHandler? TunnelDown;
    public TunnelTransport(SingBoxProcessManager manager, Func<bool>? readyProbe = null)
    {
        this.manager = manager;
        ready = readyProbe ?? (() => NetworkInterface.GetAllNetworkInterfaces().Any(i =>
            i.Name == KillSwitchPlanner.TunAlias && i.OperationalStatus == OperationalStatus.Up));
        manager.TunnelDown += (_, _) => { Volatile.Write(ref exited, true); TunnelDown?.Invoke(this, EventArgs.Empty); };
    }

    public async Task StartAsync(JsonElement configuration, CancellationToken cancellationToken)
    {
        Volatile.Write(ref exited, false);
        manager.Start(RenderConfiguration(configuration));
        // A child process merely existing is not readiness: wait for its TUN interface.
        for (var attempt = 0; attempt < 40; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref exited)) throw new IOException("连接内核在启动期间退出。");
            if (ready()) return;
            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }
        throw new TimeoutException("连接内核尚未建立虚拟网卡。");
    }

    public static JsonElement RenderConfiguration(JsonElement configuration)
    {
        var node = JsonNode.Parse(configuration.GetRawText()) as JsonObject
            ?? throw new InvalidDataException("服务器连接配置无效。");
        if (node["inbounds"] is not JsonArray inbounds) throw new InvalidDataException("服务器配置缺少虚拟网卡入口。");
        var tuns = inbounds.OfType<JsonObject>().Where(i => i["type"]?.GetValue<string>() == "tun").ToArray();
        if (tuns.Length != 1) throw new InvalidDataException("服务器配置必须包含一个虚拟网卡入口。");
        tuns[0]["interface_name"] = KillSwitchPlanner.TunAlias;
        tuns[0]["strict_route"] = true;
        tuns[0]["auto_route"] = true;
        return JsonSerializer.SerializeToElement(node);
    }
    public void Stop() => manager.Stop();
    public void Dispose() => manager.Dispose();
}
