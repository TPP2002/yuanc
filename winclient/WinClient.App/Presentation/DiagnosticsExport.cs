using System.ComponentModel;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Client;
using WinClient.Core.Diagnostics;
using WinClient.Core.Ipc;

namespace WinClient.App.Presentation;

public sealed record UiDiagnostics(string UiVersion, string ServiceVersion, string Availability, ClientSnapshot Snapshot, string UpdateStage, string UpdateMessage, string? LeakCheck = null);
public sealed record DiagnosticsExportResult(bool Written, bool ServiceIncluded, string Message);

/// <summary>导出诊断：任何情况下都写出一个脱敏文件，结果显示在「更新与诊断」页。</summary>
public static class DiagnosticsExport
{
    public const string ServiceUnreachable = "后台服务没有连上。";
    public const string ServiceTimedOut = "后台服务超过时限没有返回诊断。";
    public const string ServiceEmpty = "后台服务没有返回诊断。";
    public const string ServiceInvalid = "后台服务返回的诊断不是有效的 JSON。";
    public const string WriteFailed = "导出失败：文件没能写到所选位置，请换一个位置再试。";
    public const string ExportedPrefix = "已导出：";
    public const string UiOnlyNote = "（后台服务的记录没有取到，文件里只有界面这边的信息）";
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(45);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string DefaultFileName(DateTimeOffset localNow) => $"澳洲出口客户端-诊断-{localNow:yyyyMMdd-HHmmss}.json";

    public static string Compose(UiDiagnostics ui, DateTimeOffset now, string? service, string? serviceError, string? audit, string? selfCheck)
    {
        var serviceNode = ParseObject(service);
        var document = new JsonObject
        {
            ["schema"] = 1,
            ["exported_at"] = now.ToString("O"),
            ["ui"] = BuildUi(ui),
            ["service"] = serviceNode,
            ["service_error"] = service is not null && serviceNode is null ? ServiceInvalid : serviceError,
            ["firewall_audit"] = ParseRedacted(audit),
            ["self_check"] = ParseRedacted(selfCheck)
        };
        return document.ToJsonString(JsonOptions);
    }

    private static JsonObject BuildUi(UiDiagnostics ui)
    {
        var snapshot = ui.Snapshot;
        var apps = new JsonArray();
        foreach (var app in snapshot.RoutingApps) apps.Add(DiagnosticsRedactor.Redact(Path.GetFileName(app)));
        return new JsonObject
        {
            ["version"] = DiagnosticsRedactor.Redact(ui.UiVersion),
            ["service_version"] = DiagnosticsRedactor.Redact(ui.ServiceVersion),
            ["service_availability"] = DiagnosticsRedactor.Redact(ui.Availability),
            ["state"] = snapshot.State.ToString(),
            ["status"] = DiagnosticsRedactor.Redact(snapshot.Status),
            ["message"] = DiagnosticsRedactor.Redact(snapshot.Message),
            ["protection_active"] = snapshot.ProtectionActive,
            ["mode"] = DiagnosticsRedactor.Redact(snapshot.Mode),
            ["exit_status"] = DiagnosticsRedactor.Redact(snapshot.ExitStatus),
            ["guard_status"] = DiagnosticsRedactor.Redact(snapshot.GuardStatus),
            ["environment_enabled"] = snapshot.EnvironmentEnabled,
            ["environment_status"] = DiagnosticsRedactor.Redact(snapshot.EnvironmentStatus),
            ["self_check_status"] = DiagnosticsRedactor.Redact(snapshot.SelfCheckStatus),
            ["routing_mode"] = DiagnosticsRedactor.Redact(snapshot.RoutingMode),
            ["routing_apps"] = apps,
            ["update_stage"] = DiagnosticsRedactor.Redact(ui.UpdateStage),
            ["update_message"] = DiagnosticsRedactor.Redact(ui.UpdateMessage),
            ["leak_check"] = ui.LeakCheck is null ? null : DiagnosticsRedactor.Redact(ui.LeakCheck)
        };
    }

    private static JsonNode? ParseObject(string? text)
    {
        if (text is null) return null;
        try
        {
            var node = JsonNode.Parse(text);
            return node is JsonObject ? node : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static JsonNode? ParseRedacted(string? text)
    {
        if (text is null) return null;
        try
        {
            return JsonNode.Parse(DiagnosticsRedactor.RedactStructured(text));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static async Task<DiagnosticsExportResult> RunAsync(Func<string, CancellationToken, Task<ControlResponse>>? send,
        UiDiagnostics ui, DateTimeOffset now, string path, CancellationToken token,
        Func<string, string, CancellationToken, Task>? write = null, TimeSpan? requestTimeout = null)
    {
        string? service = null;
        string? serviceError = null;
        string? audit = null;
        string? selfCheck = null;

        async Task<(ControlResponse? Response, string? StopError)> TrySendAsync(string op)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(requestTimeout ?? RequestTimeout);
            try
            {
                return (await send!(op, timeout.Token).ConfigureAwait(false), null);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                return (null, ServiceTimedOut);
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or JsonException or
                UnauthorizedAccessException or InvalidDataException)
            {
                return (null, ServiceUnreachable);
            }
        }

        if (send is null)
        {
            serviceError = ServiceUnreachable;
        }
        else
        {
            var fallback = false;
            var first = await TrySendAsync("read_diagnostics");
            if (first.StopError is not null)
            {
                serviceError = first.StopError;
            }
            else
            {
                var response = first.Response!;
                if (!response.Ok)
                {
                    serviceError = response.Error ?? ServiceEmpty;
                    fallback = true;
                }
                else if (response.Diagnostics is null)
                {
                    serviceError = ServiceEmpty;
                    fallback = true;
                }
                else if (ParseObject(response.Diagnostics) is null)
                {
                    serviceError = ServiceInvalid;
                    fallback = true;
                }
                else
                {
                    service = response.Diagnostics;
                }
            }
            if (fallback)
            {
                var auditResponse = await TrySendAsync("read_audit");
                if (auditResponse.StopError is not null)
                {
                    serviceError = auditResponse.StopError;
                }
                else
                {
                    if (auditResponse.Response!.Ok) audit = auditResponse.Response.Audit;
                    var selfCheckResponse = await TrySendAsync("read_selfcheck");
                    if (selfCheckResponse.StopError is not null) serviceError = selfCheckResponse.StopError;
                    else if (selfCheckResponse.Response!.Ok) selfCheck = selfCheckResponse.Response.SelfCheck;
                }
            }
        }

        var text = Compose(ui, now, service, serviceError, audit, selfCheck);
        try
        {
            if (write is null) await File.WriteAllTextAsync(path, text, new UTF8Encoding(false), token).ConfigureAwait(false);
            else await write(path, text, token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or
            ArgumentException or System.Security.SecurityException)
        {
            return new(false, false, WriteFailed);
        }
        var included = service is not null;
        return new(true, included, ExportedPrefix + path + (included ? "" : UiOnlyNote));
    }

    public static bool RevealInExplorer(string path)
    {
        try
        {
            var start = new System.Diagnostics.ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
                Arguments = "/select,\"" + path + "\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = System.Diagnostics.Process.Start(start);
            return true;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }
}
