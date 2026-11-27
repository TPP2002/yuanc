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
    internal const int StaleAdapterPolls = 20;
    internal const int ReadyPolls = 40;
    internal const int SettlePolls = 8;
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    private readonly SingBoxProcessManager manager;
    private readonly Func<bool> ready;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    private bool exited;
    /// <summary>测试包打开连接内核的 warn 级日志；正式包保持配置里写死的关闭状态。</summary>
    public bool KernelLog { get; init; }
    public event EventHandler? TunnelDown;
    public TunnelTransport(SingBoxProcessManager manager, Func<bool>? readyProbe = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        this.manager = manager;
        ready = readyProbe ?? (() => NetworkInterface.GetAllNetworkInterfaces().Any(i =>
            i.Name == KillSwitchPlanner.TunAlias && i.OperationalStatus == OperationalStatus.Up));
        this.delay = delay ?? Task.Delay;
        manager.TunnelDown += (_, _) => { Volatile.Write(ref exited, true); TunnelDown?.Invoke(this, EventArgs.Empty); };
    }

    public async Task StartAsync(JsonElement configuration, CancellationToken cancellationToken)
    {
        Volatile.Write(ref exited, false);
        // 先停掉上一个内核并清残留；结束不掉时 IOException 原样往外抛，控制器按隧道断开处理。
        manager.StopAndSweep();
        // 旧内核的网卡可能还在线：最多等 5 秒它自己下线；等不到就带着「旧网卡还在」继续。
        var staleAdapter = ready();
        if (staleAdapter)
        {
            for (var attempt = 0; attempt < StaleAdapterPolls; attempt++)
            {
                await delay(PollInterval, cancellationToken).ConfigureAwait(false);
                if (ready())
                {
                    continue;
                }
                staleAdapter = false;
                break;
            }
        }
        manager.Start(RenderConfiguration(configuration, KernelLog));
        // A child process merely existing is not readiness: wait for its TUN interface.
        var settled = 0;
        for (var attempt = 0; attempt < ReadyPolls; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref exited)) throw new IOException("连接内核在启动期间退出。");
            if (ready())
            {
                // 没有旧网卡时一次就绪即可（与原来一致）；有旧网卡时必须连续稳定若干次。
                if (!staleAdapter) return;
                settled++;
                if (settled >= SettlePolls) return;
            }
            else
            {
                settled = 0;
            }
            await delay(PollInterval, cancellationToken).ConfigureAwait(false);
        }
        throw new TimeoutException("连接内核尚未建立虚拟网卡。");
    }

    public static JsonElement RenderConfiguration(JsonElement configuration) => RenderConfiguration(configuration, false);

    public static JsonElement RenderConfiguration(JsonElement configuration, bool kernelLog)
    {
        var node = JsonNode.Parse(configuration.GetRawText()) as JsonObject
            ?? throw new InvalidDataException("服务器连接配置无效。");
        if (node["inbounds"] is not JsonArray inbounds) throw new InvalidDataException("服务器配置缺少虚拟网卡入口。");
        var tuns = inbounds.OfType<JsonObject>().Where(i => i["type"]?.GetValue<string>() == "tun").ToArray();
        if (tuns.Length != 1) throw new InvalidDataException("服务器配置必须包含一个虚拟网卡入口。");
        tuns[0]["interface_name"] = KillSwitchPlanner.TunAlias;
        tuns[0]["strict_route"] = true;
        tuns[0]["auto_route"] = true;
        tuns[0]["route_address"] = new JsonArray(RouteGuard.TunRoutes.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
        // 只有测试包把顶层 log 换成 warn 级；正式包不碰配置里的 log 段，输出与改动前逐字节相同。
        if (kernelLog) node["log"] = new JsonObject { ["disabled"] = false, ["level"] = "warn", ["timestamp"] = true };
        return JsonSerializer.SerializeToElement(node);
    }
    public void Stop() => manager.Stop();
    public void Dispose() => manager.Dispose();
}
