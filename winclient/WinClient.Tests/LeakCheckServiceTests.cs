using System.IO;
using WinClient.Core.Diagnostics;
using Xunit;

namespace WinClient.Tests;

public sealed class LeakCheckServiceTests
{
    private static readonly DateTime Started = new(2026, 11, 28, 21, 3, 5);
    private static LeakCheckOptions Options(bool apps = false) => new(120, null, @"C:\out", false, apps, [], null);
    private static LeakCheckResult Result(int exitCode, params SuspiciousFlow[] flows) =>
        new(exitCode, null, new LeakVerdict(1234, 1000, 200, 2, flows));

    [Fact]
    public void UiTextCleanPutsConclusionFirst()
    {
        const string report = @"C:\ProgramData\YuanC\leakcheck\20261128-210305\leak-report.json";
        var text = LeakReportFormatter.UiText(Options(), Result(0), report, Started);
        Assert.Equal("未发现可疑流量。\n抓到 1234 个包，没能解析 2 个。\n检测于 2026-11-28 21:03，抓包 120 秒。\n报告：" + report, text);
        Assert.DoesNotContain("报告：", LeakReportFormatter.UiText(Options(), Result(0), null, Started));
    }

    [Fact]
    public void UiTextSuspiciousListsProgramFileNames()
    {
        var text = LeakReportFormatter.UiText(Options(),
            Result(1,
                new("TCP", "74.125.250.129", 443, @"C:\Program Files\Google\Chrome\Application\chrome.exe", null, 40),
                new("UDP", "192.168.1.1", 53, null, null, 12)),
            @"C:\out\leak-report.json", Started);
        var lines = text.Split('\n');
        Assert.Equal("发现可疑流量：2 条，共 52 个包。", lines[0]);
        Assert.Contains("TCP 74.125.250.129:443 chrome.exe ×40", lines);
        Assert.Contains("UDP 192.168.1.1:53 未知程序 ×12", lines);
        Assert.Contains(lines, line => line.Contains("其中发往局域网 53 端口的是域名查询"));
        Assert.DoesNotContain("Program Files", text);
    }

    [Fact]
    public void UiTextCapsFlowsAtTwenty()
    {
        var flows = Enumerable.Range(1, 25)
            .Select(index => new SuspiciousFlow("TCP", $"203.0.113.{index}", 443, null, null, 1)).ToArray();
        var text = LeakReportFormatter.UiText(Options(), Result(1, flows), null, Started);
        var lines = text.Split('\n');
        Assert.Equal("发现可疑流量：25 条，共 25 个包。", lines[0]);
        Assert.Contains("另有 5 条，见报告。", lines);
        Assert.Equal(20, lines.Count(line => line.StartsWith("TCP ")));
    }

    [Fact]
    public void UiTextAppsModeTagsFlows()
    {
        var apps = LeakReportFormatter.UiText(Options(true),
            Result(1,
                new("TCP", "74.125.250.129", 443, @"C:\Apps\chrome.exe", true, 7),
                new("TCP", "1.1.1.1", 443, @"C:\Apps\other.exe", false, 9)),
            null, Started);
        var lines = apps.Split('\n');
        Assert.Equal("发现可疑流量：1 条，共 7 个包。", lines[0]);
        Assert.Contains(lines, line => line.EndsWith(" [名单程序]", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.EndsWith(" [名单外程序(按设计直连)]", StringComparison.Ordinal));
        var clean = LeakReportFormatter.UiText(Options(true),
            Result(0, new SuspiciousFlow("TCP", "1.1.1.1", 443, @"C:\Apps\other.exe", false, 9)), null, Started);
        Assert.StartsWith("未发现可疑流量。名单外程序有 1 条直连，按设计直连。", clean);
    }

    [Fact]
    public void UiTextUnableShowsReason()
    {
        Assert.Equal("无法检测：" + LeakReportFormatter.NodeMissingUi,
            LeakReportFormatter.UiText(Options(), new LeakCheckResult(2, LeakCapture.NodeMissing, null), null, Started));
        Assert.Equal("无法检测：抓包文件格式不正确",
            LeakReportFormatter.UiText(Options(), new LeakCheckResult(2, "抓包文件格式不正确", null), null, Started));
    }

    [Fact]
    public async Task ServiceCheckerPassesNodeFromConfigAndWritesReport()
    {
        using var temp = new TempDirectory();
        LeakCheckOptions? seen = null;
        var written = new Dictionary<string, string>();
        var checker = new ServiceLeakChecker(
            (options, _) => { seen = options; return Task.FromResult(new LeakCheckResult(0, null, new LeakVerdict(10, 8, 2, 0, []))); },
            (seconds, node, directory, keep) => new LeakCheckOptions(seconds, node, directory, keep, false, [], null),
            () => "203.0.113.9", () => Started, temp.Path, (path, text) => written[path] = text);
        var text = await checker.RunAsync(CancellationToken.None);
        var directory = Path.Combine(temp.Path, "20261128-210305");
        var report = Path.Combine(directory, "leak-report.json");
        Assert.Equal(ServiceLeakChecker.Seconds, seen!.Seconds);
        Assert.Equal("203.0.113.9", seen.Node);
        Assert.Equal(directory, seen.OutputDirectory);
        Assert.False(seen.KeepCapture);
        Assert.Contains("\"verdict\": \"clean\"", written[report]);
        Assert.Equal("未发现可疑流量。\n抓到 10 个包，没能解析 0 个。\n检测于 2026-11-28 21:03，抓包 120 秒。\n报告：" + report, text);
    }

    [Fact]
    public async Task ServiceCheckerKeepsTextWhenReportCannotBeWritten()
    {
        using var temp = new TempDirectory();
        var checker = new ServiceLeakChecker(
            (_, _) => Task.FromResult(new LeakCheckResult(0, null, new LeakVerdict(10, 8, 2, 0, []))),
            (seconds, node, directory, keep) => new LeakCheckOptions(seconds, node, directory, keep, false, [], null),
            () => null, () => Started, temp.Path, (_, _) => throw new IOException("报告写不进"));
        var text = await checker.RunAsync(CancellationToken.None);
        Assert.StartsWith("未发现可疑流量。", text);
        Assert.DoesNotContain("报告：", text);
    }

    [Fact]
    public void NodeFromKernelConfigReadsMainOutboundIpv4()
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "config.json");
        File.WriteAllText(path, "{\"outbounds\":[{\"tag\":\"main\",\"server\":\"203.0.113.9\",\"server_port\":443,\"tls\":{\"server_name\":\"www.example.com\"}}]}");
        Assert.Equal("203.0.113.9", LeakCheckPlan.NodeFromKernelConfig(path));
        File.WriteAllText(path, "{\"outbounds\":[{\"tag\":\"main\",\"server\":\"node.example.com\",\"server_port\":443,\"tls\":{\"server_name\":\"www.example.com\"}}]}");
        Assert.Null(LeakCheckPlan.NodeFromKernelConfig(path));
        Assert.Null(LeakCheckPlan.NodeFromKernelConfig(Path.Combine(temp.Path, "missing.json")));
        File.WriteAllText(path, "not json");
        Assert.Null(LeakCheckPlan.NodeFromKernelConfig(path));
    }
}
