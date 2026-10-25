using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using WinClient.Core.Client;
using WinClient.Core.Diagnostics;
using WinClient.Core.Firewall;
using WinClient.Core.Network;

namespace WinClient.App.Hosting;

/// <summary>`--leak-check` 命令行入口:真机检测物理网卡上有没有发往公网的非节点流量。报告与摘要不含本机任何网卡地址。</summary>
public static class LeakCheckRunner
{
    private const int AttachParentProcess = -1;
    private const int StdOutputHandle = -11;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    public static int Run(string[] args)
    {
        AttachConsole(AttachParentProcess);
        BindConsole();
        try { Console.OutputEncoding = new UTF8Encoding(false); }
        catch (IOException) { /* 没有控制台时不设置编码。 */ }
        try
        {
            if (!ParseArguments(args, out var seconds, out var node, out var outDir, out var keep, out var error))
            {
                Console.Error.WriteLine(error);
                return 2;
            }
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.Error.WriteLine("请以管理员身份运行");
                return 2;
            }
            var routing = new RoutingSettingsStore().Read();
            var options = new LeakCheckOptions(seconds, node, outDir, keep, routing.Mode == RoutingMode.Apps, routing.Apps, LoadAuth())
            {
                AppPatterns = routing.Mode == RoutingMode.Apps ? ScopePatterns(routing.Apps) : null
            };
            var started = DateTime.Now;
            Console.WriteLine($"开始泄漏检测,抓包 {seconds} 秒,请在此期间正常使用电脑……");
            using var cancel = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
            var capture = new LeakCapture(new CommandRunner(), new SystemTcpTable(), new SystemUdpTable());
            LeakCheckResult result;
            try { result = capture.RunAsync(options, cancel.Token).GetAwaiter().GetResult(); }
            catch (OperationCanceledException) { result = new(2, "检测已被取消", null); }
            Directory.CreateDirectory(outDir);
            File.WriteAllText(Path.Combine(outDir, "leak-report.json"), LeakReportFormatter.Json(started, options, result),
                new UTF8Encoding(false));
            LeakReportFormatter.WriteSummary(Console.Out, options, result, outDir);
            return result.ExitCode;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine("泄漏检测未能完成,请确认输出目录可写。");
            return 2;
        }
    }

    private static bool ParseArguments(string[] args, out int seconds, out string? node, out string outDir, out bool keep, out string error)
    {
        seconds = 120; node = null; keep = false; error = "";
        outDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "YuanC", "leakcheck",
            DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--seconds" when i + 1 < args.Length && int.TryParse(args[++i], out var value) && value is >= 10 and <= 600:
                    seconds = value; break;
                case "--seconds": error = "--seconds 需要 10 到 600 之间的整数。"; return false;
                case "--node" when i + 1 < args.Length:
                    node = args[++i];
                    if (!IPAddress.TryParse(node, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    { error = "--node 需要 IPv4 地址。"; return false; }
                    break;
                case "--out" when i + 1 < args.Length: outDir = Path.GetFullPath(args[++i]); break;
                case "--keep-capture": keep = true; break;
                default: error = "无法识别的参数。可用:--seconds <10~600>、--node <IPv4>、--out <目录>、--keep-capture。"; return false;
            }
        }
        return true;
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
            or System.Text.Json.JsonException or UnauthorizedAccessException) { return null; }
    }

    // 窗口程序没有标准输出句柄;挂上父控制台后,若没有可用句柄就直接打开 CONOUT$。
    private static void BindConsole()
    {
        var handle = GetStdHandle(StdOutputHandle);
        if (handle != IntPtr.Zero && handle != new IntPtr(-1)) return;
        var console = CreateFile("CONOUT$", 0x40000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (console.IsInvalid) return;
        var writer = new StreamWriter(new FileStream(console, FileAccess.Write), new UTF8Encoding(false)) { AutoFlush = true };
        Console.SetOut(writer);
        Console.SetError(writer);
    }
}
