using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Firewall;

namespace WinClient.Core.Client;

public static class RoutingRenderer
{
    public static string PathPattern(string path) => "(?i)^" + Escape(path) + "$";

    /// <summary>按 RE2 元字符转义文本。</summary>
    public static string Escape(string text)
    {
        var escaped = new StringBuilder();
        foreach (var character in text)
        {
            if ("\\.+*?()|[]{}^$".Contains(character)) escaped.Append('\\');
            escaped.Append(character);
        }
        return escaped.ToString();
    }

    public static JsonElement Render(JsonElement configuration, RoutingPolicy routing, string serviceProcessPath, AuthEndpoint? auth = null,
        IReadOnlyList<string>? appPatterns = null)
    {
        if (routing.Mode == RoutingMode.Global && auth is null) return configuration;
        var root = JsonNode.Parse(configuration.GetRawText()) as JsonObject
            ?? throw new InvalidDataException("服务器连接配置无效。");
        if (root["route"] is not JsonObject route) throw new InvalidDataException("服务器配置缺少路由设置。");
        if (root["outbounds"] is not JsonArray outbounds) throw new InvalidDataException("服务器配置缺少出站设置。");
        if (!outbounds.OfType<JsonObject>().Any(outbound => Text(outbound["tag"]) == "direct"))
            outbounds.Add(new JsonObject { ["type"] = "direct", ["tag"] = "direct" });
        if (routing.Mode == RoutingMode.Apps)
        {
        if (root["dns"] is not JsonObject dns) throw new InvalidDataException("服务器配置缺少 DNS 设置。");
        if (dns["servers"] is not JsonArray servers || !servers.OfType<JsonObject>().Any(server => Text(server["detour"]) == "proxy"))
            throw new InvalidDataException("服务器配置缺少经隧道的 DNS,无法启用仅指定程序模式。");
        var patterns = appPatterns is null
            ? routing.Apps.Append(serviceProcessPath).Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.Ordinal).Select(PathPattern).ToArray()
            : appPatterns.Append(PathPattern(serviceProcessPath)).Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.Ordinal).ToArray();
        var rules = new JsonArray();
        if (route["rules"] is JsonArray previous)
            foreach (var rule in previous.OfType<JsonObject>().Where(rule => Text(rule["action"]) == "sniff" || Text(rule["protocol"]) == "dns"))
                rules.Add(rule.DeepClone());
        if (auth is not null)
            rules.Add(AuthDirectRule(serviceProcessPath, auth));
        rules.Add(new JsonObject { ["process_path_regex"] = Strings(patterns), ["ip_version"] = 6, ["action"] = "reject" });
        rules.Add(new JsonObject { ["process_path_regex"] = Strings(patterns), ["outbound"] = "proxy" });
        // 失败即关:认得出归属的名单外程序直连;认不出归属的连接(无进程信息)落到最后一条,一律拒绝。
        rules.Add(new JsonObject { ["process_path_regex"] = Strings(["(?i)^.+$"]), ["outbound"] = "direct" });
        rules.Add(new JsonObject { ["action"] = "reject" });
        route["rules"] = rules;
        route["final"] = "direct";
        }
        // DNS 保留原始 JSON 字节（含空白与转义）；其余未修改段也原样写回。
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            foreach (var property in root)
            {
                writer.WritePropertyName(property.Key);
                if (property.Key == "route" && routing.Mode == RoutingMode.Global)
                    WriteGlobalRoute(writer, configuration.GetProperty("route"), serviceProcessPath, auth!);
                else if (property.Key is "route" or "outbounds") property.Value!.WriteTo(writer);
                else writer.WriteRawValue(configuration.GetProperty(property.Key).GetRawText());
            }
            writer.WriteEndObject();
        }
        using var document = JsonDocument.Parse(output.ToArray());
        return document.RootElement.Clone();
    }

    private static JsonObject AuthDirectRule(string serviceProcessPath, AuthEndpoint auth) => new()
    {
        ["process_path_regex"] = Strings([PathPattern(serviceProcessPath)]),
        ["ip_cidr"] = Strings([auth.Address + "/32"]), ["port"] = new JsonArray(JsonValue.Create(auth.Port)), ["outbound"] = "direct"
    };

    private static void WriteGlobalRoute(Utf8JsonWriter writer, JsonElement route, string serviceProcessPath, AuthEndpoint auth)
    {
        void WriteRules(JsonElement previous)
        {
            writer.WriteStartArray();
            var original = previous.ValueKind == JsonValueKind.Array ? previous.EnumerateArray().ToArray() : [];
            var leadingSniff = original.TakeWhile(rule => rule.ValueKind == JsonValueKind.Object
                && rule.TryGetProperty("action", out var action) && action.ValueKind == JsonValueKind.String
                && action.GetString() == "sniff").Count();
            foreach (var rule in original.Take(leadingSniff)) writer.WriteRawValue(rule.GetRawText());
            AuthDirectRule(serviceProcessPath, auth).WriteTo(writer);
                foreach (var rule in original.Skip(leadingSniff))
                {
                    if (rule.ValueKind == JsonValueKind.Object && rule.TryGetProperty("outbound", out var outbound)
                        && outbound.ValueKind == JsonValueKind.String && outbound.GetString() == "direct") continue;
                    writer.WriteRawValue(rule.GetRawText());
                }
            writer.WriteEndArray();
        }
        writer.WriteStartObject();
        foreach (var property in route.EnumerateObject())
        {
            writer.WritePropertyName(property.Name);
            if (property.Name == "rules") WriteRules(property.Value);
            else writer.WriteRawValue(property.Value.GetRawText());
        }
        if (!route.TryGetProperty("rules", out _))
        {
            writer.WritePropertyName("rules");
            WriteRules(default);
        }
        writer.WriteEndObject();
    }

    private static string? Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
    private static JsonArray Strings(IEnumerable<string> values) => new(values.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
}
