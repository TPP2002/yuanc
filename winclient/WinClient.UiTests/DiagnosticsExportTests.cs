using System.IO;
using System.Text.Json.Nodes;
using WinClient.App.Presentation;
using WinClient.Core.Client;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.UiTests;

public class DiagnosticsExportTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-28T01:02:03Z");

    private static UiDiagnostics Ui(ClientSnapshot? snapshot = null) => new("0.1.0", "0.1.0", "Ready",
        snapshot ?? new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false), "idle", "");

    private static async Task<(DiagnosticsExportResult Result, string? Text)> ExportAsync(
        Func<string, CancellationToken, Task<ControlResponse>>? send, UiDiagnostics? ui = null,
        Func<string, string, CancellationToken, Task>? write = null, TimeSpan? timeout = null)
    {
        string? text = null;
        var result = await DiagnosticsExport.RunAsync(send, ui ?? Ui(), Now, "C:\\fake\\diagnostics.json",
            CancellationToken.None,
            write ?? ((_, value, _) => { text = value; return Task.CompletedTask; }), timeout);
        return (result, text);
    }

    [Fact]
    public void DefaultFileNameCarriesTimestamp()
    {
        Assert.Equal("澳洲出口客户端-诊断-20261128-090507.json",
            DiagnosticsExport.DefaultFileName(new DateTimeOffset(2026, 11, 28, 9, 5, 7, TimeSpan.FromHours(8))));
    }

    [Fact]
    public async Task WritesFileEvenWithoutService()
    {
        var (result, text) = await ExportAsync(null);
        Assert.True(result.Written);
        Assert.False(result.ServiceIncluded);
        Assert.Equal("已导出：C:\\fake\\diagnostics.json" + DiagnosticsExport.UiOnlyNote, result.Message);
        var document = JsonNode.Parse(text!)!.AsObject();
        Assert.Null(document["service"]);
        Assert.Equal("后台服务没有连上。", document["service_error"]!.GetValue<string>());
        Assert.Equal("0.1.0", document["ui"]!["version"]!.GetValue<string>());
    }

    [Fact]
    public async Task UsesServiceDiagnosticsWhenAvailable()
    {
        var ops = new List<string>();
        var (result, text) = await ExportAsync((op, _) =>
        {
            ops.Add(op);
            return Task.FromResult(new ControlResponse(1, true, Diagnostics: "{\"schema\":1}"));
        });
        Assert.Equal(new[] { "read_diagnostics" }, ops);
        Assert.True(result.ServiceIncluded);
        Assert.Equal("已导出：C:\\fake\\diagnostics.json", result.Message);
        Assert.Equal(1, JsonNode.Parse(text!)!["service"]!["schema"]!.GetValue<int>());
    }

    [Fact]
    public async Task FallsBackToAuditAndSelfCheckWhenUnsupported()
    {
        var ops = new List<string>();
        var (result, text) = await ExportAsync((op, _) =>
        {
            ops.Add(op);
            return Task.FromResult(op switch
            {
                "read_diagnostics" => new ControlResponse(1, false, "不支持的指令"),
                "read_audit" => new ControlResponse(2, true, Audit: "{\"a\":1}"),
                _ => new ControlResponse(3, true, SelfCheck: "{\"b\":2}")
            });
        });
        Assert.Equal(new[] { "read_diagnostics", "read_audit", "read_selfcheck" }, ops);
        var document = JsonNode.Parse(text!)!.AsObject();
        Assert.Null(document["service"]);
        Assert.Equal("不支持的指令", document["service_error"]!.GetValue<string>());
        Assert.Equal(1, document["firewall_audit"]!["a"]!.GetValue<int>());
        Assert.Equal(2, document["self_check"]!["b"]!.GetValue<int>());
        Assert.True(result.Written);
    }

    [Fact]
    public async Task WritesFileWhenNothingWasEverRecorded()
    {
        var (result, text) = await ExportAsync((op, _) => Task.FromResult(op == "read_diagnostics"
            ? new ControlResponse(1, false, "不支持的指令")
            : new ControlResponse(2, true)));
        Assert.True(result.Written);
        var document = JsonNode.Parse(text!)!.AsObject();
        Assert.Null(document["firewall_audit"]);
        Assert.Null(document["self_check"]);
    }

    [Fact]
    public async Task PipeFailureStillWritesFile()
    {
        var ops = 0;
        var (result, text) = await ExportAsync((_, _) =>
        {
            ops++;
            throw new IOException("broken");
        });
        Assert.True(result.Written);
        Assert.Equal(1, ops);
        Assert.Equal("后台服务没有连上。", JsonNode.Parse(text!)!["service_error"]!.GetValue<string>());
    }

    [Fact]
    public async Task SlowServiceTimesOutAndStillWritesFile()
    {
        var (result, text) = await ExportAsync(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new ControlResponse(1, true);
        }, timeout: TimeSpan.FromMilliseconds(50));
        Assert.True(result.Written);
        Assert.Equal("后台服务超过时限没有返回诊断。",
            JsonNode.Parse(text!)!["service_error"]!.GetValue<string>());
    }

    [Fact]
    public async Task InvalidServiceJsonIsDroppedWithError()
    {
        var ops = new List<string>();
        var (_, text) = await ExportAsync((op, _) =>
        {
            ops.Add(op);
            return Task.FromResult(op == "read_diagnostics"
                ? new ControlResponse(1, true, Diagnostics: "不是 JSON")
                : new ControlResponse(2, true));
        });
        Assert.Equal(new[] { "read_diagnostics", "read_audit", "read_selfcheck" }, ops);
        var document = JsonNode.Parse(text!)!.AsObject();
        Assert.Null(document["service"]);
        Assert.Equal("后台服务返回的诊断不是有效的 JSON。", document["service_error"]!.GetValue<string>());
    }

    [Fact]
    public async Task WriteFailureIsReportedNotThrown()
    {
        var (result, _) = await ExportAsync((_, _) => Task.FromResult(new ControlResponse(1, false, "x")),
            write: (_, _, _) => throw new UnauthorizedAccessException());
        Assert.False(result.Written);
        Assert.Equal("导出失败：文件没能写到所选位置，请换一个位置再试。", result.Message);
    }

    [Fact]
    public async Task UiSectionOmitsExitIpAndRedactsMessage()
    {
        var snapshot = new ClientSnapshot(ConnectionState.Disconnected, "未连接", @"访问 C:\Users\alice\x", false)
        {
            ExitIp = "8.8.8.8",
            RoutingApps = [@"C:\Users\alice\App\chrome.exe"]
        };
        var (_, text) = await ExportAsync(null, Ui(snapshot));
        Assert.DoesNotContain("8.8.8.8", text);
        Assert.DoesNotContain("alice", text);
        Assert.Equal(new[] { "chrome.exe" },
            JsonNode.Parse(text!)!["ui"]!["routing_apps"]!.AsArray().Select(node => node!.GetValue<string>()));
    }

    [Fact]
    public void ComposeKeepsKeyOrder()
    {
        var document = JsonNode.Parse(DiagnosticsExport.Compose(Ui(), Now, null, null, null, null))!.AsObject();
        Assert.Equal(new[] { "schema", "exported_at", "ui", "service", "service_error", "firewall_audit", "self_check" },
            document.Select(pair => pair.Key));
    }
}
