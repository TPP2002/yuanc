using System.Text;
using WinClient.Core.Firewall;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

/// <summary>后台服务里跑一次泄漏检测,返回给界面看的中文结论。</summary>
public interface ILeakChecker
{
    Task<string> RunAsync(CancellationToken token);
}

/// <summary>界面按钮用的检测:固定抓 120 秒,节点地址先从内核配置里取,报告写到数据目录,不留抓包文件。</summary>
public sealed class ServiceLeakChecker(
    Func<LeakCheckOptions, CancellationToken, Task<LeakCheckResult>> capture,
    Func<int, string?, string, bool, LeakCheckOptions> plan,
    Func<string?> node, Func<DateTime> now, string root, Action<string, string>? write = null) : ILeakChecker
{
    public const int Seconds = 120;
    private readonly Action<string, string> writeReport = write ?? WriteReport;

    public async Task<string> RunAsync(CancellationToken token)
    {
        var started = now();
        var directory = Path.Combine(root, started.ToString("yyyyMMdd-HHmmss"));
        var options = plan(Seconds, node(), directory, false);
        var result = await capture(options, token).ConfigureAwait(false);
        string? report = Path.Combine(directory, "leak-report.json");
        try { writeReport(report, LeakReportFormatter.Json(started, options, result)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // 报告没写成不影响结论,界面上不给路径。
            report = null;
        }
        return LeakReportFormatter.UiText(options, result, report, started);
    }

    public static ServiceLeakChecker CreateProduction()
    {
        var capture = new LeakCapture(new CommandRunner(), new SystemTcpTable(), new SystemUdpTable());
        return new(capture.RunAsync, LeakCheckPlan.Build,
            () => LeakCheckPlan.NodeFromKernelConfig(LeakCheckPlan.KernelConfigPath), () => DateTime.Now, LeakCheckPlan.OutputRoot);
    }

    private static void WriteReport(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text, new UTF8Encoding(false));
    }
}
