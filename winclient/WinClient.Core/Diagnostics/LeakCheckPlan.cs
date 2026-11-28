using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Firewall;

namespace WinClient.Core.Diagnostics;

/// <summary>泄漏检测的入参怎么拼:命令行入口和后台服务共用,代理范围、名单程序的连带范围、鉴权地址的取法一致。</summary>
public static class LeakCheckPlan
{
    public static string OutputRoot => Path.Combine(ClientSettings.DataDirectory, "leakcheck");
    public static string KernelConfigPath => Path.Combine(ClientSettings.DataDirectory, "run", "config.json");

    public static LeakCheckOptions Build(int seconds, string? node, string outputDirectory, bool keepCapture)
    {
        var routing = new RoutingSettingsStore().Read();
        var apps = routing.Mode == RoutingMode.Apps;
        return new LeakCheckOptions(seconds, node, outputDirectory, keepCapture, apps, routing.Apps, LoadAuth())
        {
            AppPatterns = apps ? ScopePatterns(routing.Apps) : null
        };
    }

    /// <summary>从内核配置里取主通道的节点地址。读不到、不是 JSON、不是 IPv4 字面量都返回 null(调用方退回连接表),不抛异常。</summary>
    public static string? NodeFromKernelConfig(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var host = ReachProbe.MainTargetFrom(document.RootElement)?.Host;
            return IPAddress.TryParse(host, out var address) && address.AddressFamily == AddressFamily.InterNetwork ? host : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException
            or NotSupportedException or InvalidOperationException) { return null; }
    }

    // 与客户端连接时同一算法算出每个名单程序的连带范围匹配式;单个解析失败时退回只认该程序本身。
    private static string[] ScopePatterns(IReadOnlyList<string> apps)
    {
        var folders = AppScopeResolver.SystemFolders();
        var fileSystem = new SystemAppScopeFileSystem();
        var patterns = new List<string>();
        foreach (var path in apps)
        {
            try { patterns.Add(AppScopeResolver.Resolve(path, folders, fileSystem).Pattern); }
            catch (Exception) { patterns.Add(RoutingRenderer.PathPattern(path)); }
        }
        return [.. patterns];
    }

    // 分发版鉴权地址;读不到就不放行任何鉴权地址。
    private static AuthEndpoint? LoadAuth()
    {
        try { return ClientSettings.Load()?.AuthEndpoint; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UriFormatException or FormatException
            or JsonException or UnauthorizedAccessException) { return null; }
    }
}
