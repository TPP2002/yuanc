using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Client;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Ipc;

namespace WinClient.Core.Diagnostics;

public sealed class DiagnosticsSources
{
    public required string RunDirectory { get; init; }
    public required Func<ClientSnapshot> Snapshot { get; init; }
    public string Version { get; init; } = "";
    public bool TestBuild { get; init; }
    public Func<bool?>? Desired { get; init; }
    public Func<IReadOnlyList<string>>? WfpFilterNames { get; init; }
    public Func<IReadOnlyList<AdapterInfo>?>? Adapters { get; init; }
    public Func<CancellationToken, Task<FirewallStateResult>>? Firewall { get; init; }
    public Func<CancellationToken, Task<NetworkStateResult>>? Network { get; init; }
    public Func<string?>? Audit { get; init; }
    public Func<string?>? SelfCheck { get; init; }
    public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;
}

public static class DiagnosticsCollector
{
    public const int MaxEncodedBytes = 900 * 1024;
    public static readonly IReadOnlyList<string> LogNames = ["service.log", "connect.log", "sing-box.log", "update.log", "killswitch-recovery.log"];
    internal static readonly int[] LineBudgets = [400, 200, 100, 40, 10, 0];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static async Task<string> CollectAsync(DiagnosticsSources sources, CancellationToken token = default)
    {
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);
        var snapshot = Call(sources.Snapshot, "snapshot", errors);
        var desired = sources.Desired is null ? null : Call(sources.Desired, "desired", errors);
        var wfp = sources.WfpFilterNames is null ? null : Call(sources.WfpFilterNames, "wfp_filters", errors);
        var adapters = sources.Adapters is null ? null : Call(sources.Adapters, "adapters", errors);
        FirewallStateResult? firewall = null;
        if (sources.Firewall is not null)
        {
            try { firewall = await sources.Firewall(token).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { errors["firewall"] = ex.GetType().Name; }
        }
        NetworkStateResult? network = null;
        if (sources.Network is not null)
        {
            try { network = await sources.Network(token).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { errors["network"] = ex.GetType().Name; }
        }
        var audit = sources.Audit is null ? null : Call(sources.Audit, "firewall_audit", errors);
        var selfCheck = sources.SelfCheck is null ? null : Call(sources.SelfCheck, "self_check", errors);
        var auditNode = ParseRedacted(audit, "firewall_audit", errors);
        var selfCheckNode = ParseRedacted(selfCheck, "self_check", errors);
        JsonNode? firewallNode = null;
        if (firewall?.Json is { } firewallJson)
        {
            try { firewallNode = JsonNode.Parse(firewallJson); }
            catch (JsonException) { firewallNode = null; }
        }
        JsonNode? networkNode = null;
        if (network?.Json is { } networkJson)
        {
            try { networkNode = RedactNetwork(JsonNode.Parse(networkJson)); }
            catch (JsonException) { errors["network"] = "不是有效的 JSON"; }
        }

        var logReads = new List<LogTailResult>();
        foreach (var name in LogNames) logReads.Add(LogTail.Read(sources.RunDirectory, name, LineBudgets[0]));

        var statePath = Path.Combine(sources.RunDirectory, "killswitch-state.json");
        var auditPath = Path.Combine(sources.RunDirectory, "firewall-audit.json");
        var stateExists = File.Exists(statePath);
        var auditExists = File.Exists(auditPath);
        long stateBytes = 0, auditBytes = 0;
        string? stateModified = null, auditModified = null;
        JsonObject? stateSummary = null;
        if (stateExists)
        {
            try
            {
                stateBytes = new FileInfo(statePath).Length;
                stateModified = File.GetLastWriteTimeUtc(statePath).ToString("O");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                stateBytes = 0;
                stateModified = null;
                errors["killswitch_state_file"] = ex.GetType().Name;
            }
            try { stateSummary = Summarize(File.ReadAllText(statePath), errors); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        if (auditExists)
        {
            try
            {
                auditBytes = new FileInfo(auditPath).Length;
                auditModified = File.GetLastWriteTimeUtc(auditPath).ToString("O");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                auditBytes = 0;
                auditModified = null;
                errors["firewall_audit_file"] = ex.GetType().Name;
            }
        }

        var omitted = new List<string>();
        var input = new BuildInput(sources, snapshot, desired, wfp, adapters, firewallNode, firewall?.Error,
            networkNode, network?.Error, logReads,
            auditNode, selfCheckNode, omitted, errors, stateExists, stateBytes, stateModified, stateSummary,
            auditExists, auditBytes, auditModified);
        foreach (var maxLines in LineBudgets)
        {
            var text = Build(input, maxLines, withAudit: true, withSelfCheck: true, withAdapters: true).ToJsonString(JsonOptions);
            if (EncodedBytes(text) <= MaxEncodedBytes) return text;
        }
        omitted.Add("firewall_audit");
        var withoutAudit = Build(input, LineBudgets[^1], withAudit: false, withSelfCheck: true, withAdapters: true)
            .ToJsonString(JsonOptions);
        if (EncodedBytes(withoutAudit) <= MaxEncodedBytes) return withoutAudit;
        omitted.Add("self_check");
        var withoutSelfCheck = Build(input, LineBudgets[^1], withAudit: false, withSelfCheck: false, withAdapters: true)
            .ToJsonString(JsonOptions);
        if (EncodedBytes(withoutSelfCheck) <= MaxEncodedBytes) return withoutSelfCheck;
        omitted.Add("adapters");
        return Build(input, LineBudgets[^1], withAudit: false, withSelfCheck: false, withAdapters: false)
            .ToJsonString(JsonOptions);
    }

    internal static int EncodedBytes(string diagnostics) =>
        ControlProtocol.Utf8.GetByteCount(ControlProtocol.Encode(new ControlResponse(0, true, Diagnostics: diagnostics)));

    private sealed record BuildInput(DiagnosticsSources Sources, ClientSnapshot? Snapshot, bool? Desired,
        IReadOnlyList<string>? Wfp, IReadOnlyList<AdapterInfo>? Adapters, JsonNode? Firewall, string? FirewallError,
        JsonNode? Network, string? NetworkError,
        IReadOnlyList<LogTailResult> Logs, JsonNode? Audit, JsonNode? SelfCheck, IReadOnlyList<string> Omitted,
        IReadOnlyDictionary<string, string> Errors, bool StateExists, long StateBytes, string? StateModified,
        JsonObject? StateSummary, bool AuditExists, long AuditBytes, string? AuditModified);

    private static JsonObject Build(BuildInput input, int maxLines, bool withAudit, bool withSelfCheck, bool withAdapters)
    {
        var sources = input.Sources;
        var now = sources.Now();
        var errors = new JsonObject();
        foreach (var pair in input.Errors) errors[pair.Key] = pair.Value;
        var system = new JsonObject
        {
            ["os"] = RuntimeInformation.OSDescription,
            ["arch"] = RuntimeInformation.OSArchitecture.ToString(),
            ["culture"] = CultureInfo.CurrentUICulture.Name,
            ["time_zone"] = TimeZoneInfo.Local.Id,
            ["utc_offset_minutes"] = (int)TimeZoneInfo.Local.GetUtcOffset(now).TotalMinutes,
            ["uptime_minutes"] = Environment.TickCount64 / 60000
        };
        var result = new JsonObject
        {
            ["schema"] = 1,
            ["collected_at"] = now.ToString("O"),
            ["version"] = sources.Version,
            ["test_build"] = sources.TestBuild,
            ["system"] = system,
            ["snapshot"] = BuildSnapshot(input.Snapshot),
            ["desired"] = input.Desired is null ? (JsonNode?)null : JsonValue.Create(input.Desired.Value),
            ["killswitch"] = new JsonObject
            {
                ["state"] = new JsonObject
                {
                    ["exists"] = input.StateExists,
                    ["bytes"] = input.StateBytes,
                    ["modified_at"] = input.StateModified,
                    ["summary"] = input.StateSummary?.DeepClone()
                },
                ["audit_file"] = new JsonObject
                {
                    ["exists"] = input.AuditExists,
                    ["bytes"] = input.AuditBytes,
                    ["modified_at"] = input.AuditModified
                },
                ["wfp_off"] = File.Exists(Path.Combine(sources.RunDirectory, "wfp-off")),
                ["route_off"] = File.Exists(Path.Combine(sources.RunDirectory, "route-off"))
            },
            ["wfp_filters"] = BuildWfp(input.Wfp),
            ["adapters"] = withAdapters ? BuildAdapters(input.Adapters) : null,
            ["firewall"] = input.Firewall?.DeepClone(),
            ["firewall_error"] = input.FirewallError,
            ["network"] = input.Network?.DeepClone(),
            ["network_error"] = input.NetworkError,
            ["logs"] = BuildLogs(input.Logs, maxLines),
            ["firewall_audit"] = withAudit ? input.Audit?.DeepClone() : null,
            ["self_check"] = withSelfCheck ? input.SelfCheck?.DeepClone() : null,
            ["omitted"] = BuildOmitted(input.Omitted),
            ["errors"] = errors
        };
        // 采集来源没接路由与 DNS 探测时（只在单元测试里出现）不带这两个键，根键清单与次序保持原样。
        if (sources.Network is null)
        {
            result.Remove("network");
            result.Remove("network_error");
        }
        return result;
    }

    private static JsonObject? BuildSnapshot(ClientSnapshot? snapshot)
    {
        if (snapshot is null) return null;
        var apps = new JsonArray();
        foreach (var app in snapshot.RoutingApps) apps.Add(DiagnosticsRedactor.Redact(Path.GetFileName(app)));
        return new JsonObject
        {
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
            ["routing_apps"] = apps
        };
    }

    private static JsonObject? BuildWfp(IReadOnlyList<string>? names)
    {
        if (names is null) return null;
        var array = new JsonArray();
        foreach (var name in names) array.Add(DiagnosticsRedactor.Redact(name));
        return new JsonObject { ["count"] = names.Count, ["names"] = array };
    }

    private static JsonArray? BuildAdapters(IReadOnlyList<AdapterInfo>? adapters)
    {
        if (adapters is null) return null;
        var array = new JsonArray();
        foreach (var adapter in adapters)
        {
            array.Add(new JsonObject
            {
                ["name"] = DiagnosticsRedactor.Redact(adapter.Name),
                ["description"] = DiagnosticsRedactor.Redact(adapter.Description),
                ["ipv4"] = BuildAddresses(adapter.Ipv4),
                ["ipv6"] = BuildAddresses(adapter.Ipv6)
            });
        }
        return array;
    }

    private static JsonArray BuildAddresses(IReadOnlyList<AdapterAddress> addresses)
    {
        var array = new JsonArray();
        foreach (var address in addresses)
            array.Add(DiagnosticsRedactor.Redact(address.Address) + "/" + address.PrefixLength);
        return array;
    }

    private static JsonObject BuildLogs(IReadOnlyList<LogTailResult> logs, int maxLines)
    {
        var result = new JsonObject();
        foreach (var log in logs)
        {
            IReadOnlyList<string> lines = log.Lines;
            var truncated = log.Truncated;
            if (maxLines <= 0)
            {
                truncated |= lines.Count > 0;
                lines = [];
            }
            else if (lines.Count > maxLines)
            {
                lines = lines.Skip(lines.Count - maxLines).ToArray();
                truncated = true;
            }
            var array = new JsonArray();
            foreach (var line in lines)
                array.Add(log.Name == "sing-box.log" ? DiagnosticsRedactor.MaskDomains(line) : line);
            result[log.Name] = new JsonObject
            {
                ["missing"] = log.Missing,
                ["bytes"] = log.Bytes,
                ["truncated"] = truncated,
                ["error"] = log.Error,
                ["lines"] = array
            };
        }
        return result;
    }

    private static JsonArray BuildOmitted(IReadOnlyList<string> omitted)
    {
        var array = new JsonArray();
        foreach (var name in omitted) array.Add(name);
        return array;
    }

    private static JsonObject? Summarize(string text, Dictionary<string, string> errors)
    {
        try
        {
            if (JsonNode.Parse(text) is not JsonObject root)
            {
                errors["killswitch_state"] = "不是有效的 JSON";
                return null;
            }
            var summary = new JsonObject();
            foreach (var pair in root)
            {
                var name = pair.Key;
                switch (pair.Value)
                {
                    case null:
                        summary[name] = null;
                        break;
                    case JsonArray array:
                        summary[name + "_count"] = array.Count;
                        // 恢复记录里的 profiles 另给数组，导出里看得到套用前保存的三档默认出站。
                        if (name == "profiles") summary[name] = SummarizeProfiles(array);
                        break;
                    case JsonObject child:
                        var keys = new JsonArray();
                        foreach (var property in child) keys.Add(property.Key);
                        summary[name + "_keys"] = keys;
                        break;
                    case JsonValue scalar when scalar.TryGetValue<string>(out var textValue):
                        summary[name] = DiagnosticsRedactor.Redact(textValue);
                        break;
                    default:
                        summary[name] = JsonNode.Parse(pair.Value!.ToJsonString());
                        break;
                }
            }
            return summary;
        }
        catch (JsonException)
        {
            errors["killswitch_state"] = "不是有效的 JSON";
            return null;
        }
    }

    private static JsonArray SummarizeProfiles(JsonArray profiles)
    {
        var result = new JsonArray();
        foreach (var item in profiles)
        {
            if (item is not JsonObject profile) continue;
            var copy = new JsonObject();
            foreach (var property in profile)
            {
                if (property.Key is not ("Name" or "DefaultOutboundAction" or "Enabled")) continue;
                copy[property.Key] = property.Value is JsonValue scalar && scalar.TryGetValue<string>(out var text)
                    ? JsonValue.Create(DiagnosticsRedactor.Redact(text))
                    : JsonNode.Parse(property.Value?.ToJsonString() ?? "null");
            }
            result.Add(copy);
        }
        return result;
    }

    /// <summary>路由与 DNS 现状里的字符串值都脱敏；路由前缀只有 /0、/1、/2 三种长度，原样保留。</summary>
    private static JsonNode? RedactNetwork(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                var copy = new JsonObject();
                foreach (var pair in obj)
                {
                    if (pair.Value is null)
                        copy[pair.Key] = null;
                    else if (pair.Key == "prefix" && pair.Value is JsonValue prefix && prefix.TryGetValue<string>(out var kept))
                        copy[pair.Key] = kept;
                    else
                        copy[pair.Key] = RedactNetwork(pair.Value);
                }
                return copy;
            case JsonArray array:
                var items = new JsonArray();
                foreach (var item in array) items.Add(RedactNetwork(item));
                return items;
            case JsonValue value when value.TryGetValue<string>(out var text):
                return DiagnosticsRedactor.Redact(text);
            default:
                // 数字与布尔值原样复制一份脱离父节点，避免重新挂载。
                return node?.DeepClone();
        }
    }

    private static JsonNode? ParseRedacted(string? text, string name, Dictionary<string, string> errors)
    {
        if (text is null) return null;
        try
        {
            var node = JsonNode.Parse(DiagnosticsRedactor.RedactStructured(text));
            if (node is not null) return node;
        }
        catch (JsonException) { }
        errors[name] = "不是有效的 JSON";
        return null;
    }

    private static T Call<T>(Func<T> source, string name, Dictionary<string, string> errors)
    {
        try { return source(); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            errors[name] = ex.GetType().Name;
            return default!;
        }
    }
}
