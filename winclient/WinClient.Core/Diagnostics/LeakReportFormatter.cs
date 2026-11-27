using System.Net;
using System.Text.Json;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

/// <summary>生成 leak-report.json(snake_case)与终端中文摘要。两者都只含对端地址,不含本机任何网卡地址。</summary>
public static class LeakReportFormatter
{
    private const int SummaryLimit = 20;
    private const string LanDnsHint = "其中发往局域网 53 端口的是域名查询:路由器会把它转给所在地运营商的解析器。";

    public static string Json(DateTime startedAt, LeakCheckOptions options, LeakCheckResult result)
    {
        var verdict = result.Verdict;
        var report = new Dictionary<string, object?>
        {
            ["started_at"] = startedAt.ToString("yyyy-MM-ddTHH:mm:sszzz"),
            ["seconds"] = options.Seconds,
            ["mode"] = options.AppsMode ? "apps" : "global",
            ["total"] = verdict?.Total ?? 0,
            ["tunnel"] = verdict?.Tunnel ?? 0,
            ["allowed"] = verdict?.Allowed ?? 0,
            ["unparsed"] = verdict?.Unparsed ?? 0,
            ["suspicious"] = (verdict?.Suspicious ?? Array.Empty<SuspiciousFlow>()).Select(flow => new Dictionary<string, object?>
            {
                ["protocol"] = flow.Protocol, ["remote"] = flow.Remote, ["remote_port"] = flow.RemotePort,
                ["process"] = flow.Process, ["listed"] = flow.Listed, ["count"] = flow.Count
            }).ToArray(),
            ["verdict"] = result.ExitCode switch { 0 => "clean", 1 => "suspicious", _ => "unavailable" },
            ["reason"] = result.Reason ?? Conclusion(options, result)
        };
        return JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    public static void WriteSummary(TextWriter output, LeakCheckOptions options, LeakCheckResult result, string outDir)
    {
        output.WriteLine();
        if (result.Verdict is not { } verdict)
        {
            output.WriteLine("结论:无法检测");
            output.WriteLine("原因:" + result.Reason);
            return;
        }
        output.WriteLine($"共抓到 {verdict.Total} 个包:隧道内 {verdict.Tunnel},放行 {verdict.Allowed},未解析 {verdict.Unparsed},可疑 {verdict.Suspicious.Sum(flow => flow.Count)}。");
        foreach (var flow in verdict.Suspicious.Take(SummaryLimit))
        {
            var program = flow.Process is null ? "未知程序" : Path.GetFileName(flow.Process);
            var tag = !options.AppsMode ? "" : flow.Listed switch
            {
                true => " [名单程序]", false => " [名单外程序(按设计直连)]", _ => " [归属未知]"
            };
            output.WriteLine($"  {flow.Protocol} {Endpoint(flow)} {program} ×{flow.Count}{tag}");
        }
        if (verdict.Suspicious.Count > SummaryLimit)
            output.WriteLine($"  …… 另有 {verdict.Suspicious.Count - SummaryLimit} 条可疑流,见报告。");
        if (!options.AppsMode && verdict.Suspicious.Any(flow => flow.RemotePort == 53
            && IPAddress.TryParse(flow.Remote, out var peer) && !PublicAddress.IsPublic(peer)))
            output.WriteLine("  " + LanDnsHint);
        output.WriteLine("结论:" + (result.ExitCode == 0 ? "未发现可疑流量。" : "发现可疑流量!") + Conclusion(options, result));
        output.WriteLine("报告:" + Path.Combine(outDir, "leak-report.json"));
    }

    private static string Endpoint(SuspiciousFlow flow) =>
        flow.Remote.Contains(':') ? $"[{flow.Remote}]:{flow.RemotePort}" : $"{flow.Remote}:{flow.RemotePort}";

    private static string Conclusion(LeakCheckOptions options, LeakCheckResult result)
    {
        if (result.ExitCode == 1)
            return options.AppsMode ? "存在名单程序或归属未知的发往公网的流量。" : "物理网卡上有发往公网且不是节点或鉴权的流量。";
        if (result.Verdict is { Suspicious.Count: > 0 }) return "仅有名单外程序的直连流量(按设计直连)。";
        return "物理网卡上没有发往公网的非节点流量。";
    }
}
