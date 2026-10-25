using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

/// <param name="Seconds">抓包时长(秒)。</param>
/// <param name="Node">节点 IPv4;为空时从隧道内核的已建立连接里取。</param>
public sealed record LeakCheckOptions(int Seconds, string? Node, string OutputDirectory, bool KeepCapture,
    bool AppsMode, IReadOnlyList<string> Apps, AuthEndpoint? Auth)
{
    /// <summary>客户端连带范围匹配式(格式同 AppScope.Pattern);仅指定程序模式下由调用方填入。</summary>
    public IReadOnlyList<string>? AppPatterns { get; init; }
}

/// <summary>ExitCode:0 未发现可疑流量,1 发现可疑流量,2 无法检测(Verdict 为 null,Reason 给出中文原因)。</summary>
public sealed record LeakCheckResult(int ExitCode, string? Reason, LeakVerdict? Verdict);

/// <summary>编排一次检测:pktmon 只抓网卡 → 转 pcapng → 解析 → 按连接表归属归类。不输出任何本机网卡地址。</summary>
public sealed class LeakCapture(ICommandRunner runner, ITcpTable tcp, IUdpTable udp,
    Func<IReadOnlySet<IPAddress>?>? localAddresses = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    private const string NodeMissing = "未找到隧道内核的连接，请先连接，或用 --node 指定节点地址";
    private readonly Func<TimeSpan, CancellationToken, Task> wait = delay ?? ((span, cancel) => Task.Delay(span, cancel));
    private readonly Func<IReadOnlySet<IPAddress>?> locals = localAddresses ?? SystemLocalAddresses;

    public async Task<LeakCheckResult> RunAsync(LeakCheckOptions options, CancellationToken token)
    {
        var nodes = ResolveNodes(options.Node);
        if (nodes is null) return Unable(options.Node is { Length: > 0 } ? "节点地址不是有效的 IPv4 地址" : NodeMissing);
        var local = locals();
        if (local is null) return Unable("无法读取本机网卡信息");
        Directory.CreateDirectory(options.OutputDirectory);
        var etl = Path.Combine(options.OutputDirectory, "capture.etl");
        var pcap = Path.Combine(options.OutputDirectory, "capture.pcapng");
        var sampler = new ConnectionOwnerSampler(tcp, udp);
        var started = false;
        try
        {
            if (await Step(["filter", "remove"], token) is { } filterFailed) return Unable(filterFailed);
            if (await Step(["start", "--capture", "--comp", "nics", "--file-name", etl], token) is { } startFailed) return Unable(startFailed);
            started = true;
            for (var i = 0; i < Math.Max(1, options.Seconds) * 2; i++)
            {
                sampler.Sample();
                await wait(ConnectionOwnerSampler.Interval, token).ConfigureAwait(false);
            }
            sampler.Sample();
            started = false;
            if (await Step(["stop"], CancellationToken.None) is { } stopFailed) return Unable(stopFailed);
            if (await Step(["etl2pcap", etl, "--out", pcap], token) is { } convertFailed) return Unable(convertFailed);
            return Analyze(options, pcap, local, nodes, sampler);
        }
        finally
        {
            // 只要 start 成功过就保证 stop 一次,失败也不能把抓包留在后台。
            if (started) await Step(["stop"], CancellationToken.None).ConfigureAwait(false);
            if (!options.KeepCapture) { TryDelete(etl); TryDelete(pcap); }
        }
    }

    private static LeakCheckResult Analyze(LeakCheckOptions options, string pcap, IReadOnlySet<IPAddress> local,
        IReadOnlySet<IPAddress> nodes, ConnectionOwnerSampler sampler)
    {
        try
        {
            using var stream = File.OpenRead(pcap);
            var auth = options.Auth is { } endpoint ? new IPEndPoint(endpoint.Address, endpoint.Port) : null;
            var context = new LeakContext(local, nodes, auth, options.AppsMode, options.Apps)
            {
                AppPatterns = options.AppPatterns
            };
            var verdict = LeakClassifier.Classify(PcapNgReader.Read(stream), context, sampler.Owner);
            return new(LeakClassifier.ExitCode(verdict, options.AppsMode), null, verdict);
        }
        catch (InvalidDataException) { return Unable("抓包文件格式不正确"); }
        catch (IOException) { return Unable("无法读取抓包文件"); }
    }

    private IReadOnlySet<IPAddress>? ResolveNodes(string? node)
    {
        if (!string.IsNullOrWhiteSpace(node))
            return IPAddress.TryParse(node.Trim(), out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? new HashSet<IPAddress> { ip } : null;
        try
        {
            var found = tcp.Snapshot()
                .Where(entry => entry.State == 5 && entry.ProcessPath is not null &&
                    string.Equals(Path.GetFileName(entry.ProcessPath), "sing-box.exe", StringComparison.OrdinalIgnoreCase) &&
                    entry.Remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && PublicAddress.IsPublic(entry.Remote))
                .Select(entry => entry.Remote).ToHashSet();
            return found.Count > 0 ? found : null;
        }
        catch (Win32Exception) { return null; }
    }

    private async Task<string?> Step(string[] arguments, CancellationToken token)
    {
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe"),
            CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        var label = "pktmon " + arguments[0];
        try
        {
            var result = await runner.RunAsync(info, token).ConfigureAwait(false);
            return result.ExitCode == 0 ? null : $"{label} 执行失败，退出码 {result.ExitCode}。需要 Windows 10 2004 及以上版本并以管理员身份运行";
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        { return $"无法运行 {label}，请确认系统自带 pktmon(Windows 10 2004 及以上)"; }
    }

    private static LeakCheckResult Unable(string reason) => new(2, reason, null);

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static IReadOnlySet<IPAddress>? SystemLocalAddresses()
    {
        var adapters = new SystemAdapterProbe().Snapshot();
        if (adapters is null) return null;
        var set = new HashSet<IPAddress>();
        foreach (var address in adapters.SelectMany(adapter => adapter.Ipv4.Concat(adapter.Ipv6)))
        {
            // IPv6 文本可能带 %作用域,去掉后再解析。
            var text = address.Address.Split('%')[0];
            if (IPAddress.TryParse(text, out var ip)) set.Add(ip);
        }
        return set;
    }
}
