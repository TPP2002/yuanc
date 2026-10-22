using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Firewall;

namespace WinClient.Core.Client;

public static class RoutingRenderer
{
    public static string PathPattern(string path)
    {
        var pattern = new StringBuilder("(?i)^");
        foreach (var character in path)
        {
            if ("\\.+*?()|[]{}^$".Contains(character)) pattern.Append('\\');
            pattern.Append(character);
        }
        return pattern.Append('$').ToString();
    }

    public static JsonElement Render(JsonElement configuration, RoutingPolicy routing, string serviceProcessPath, AuthEndpoint? auth = null)
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
        var patterns = routing.Apps.Append(serviceProcessPath).Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.Ordinal).Select(PathPattern).ToArray();
        var rules = new JsonArray();
        if (route["rules"] is JsonArray previous)
            foreach (var rule in previous.OfType<JsonObject>().Where(rule => Text(rule["protocol"]) == "dns"))
                rules.Add(rule.DeepClone());
        if (auth is not null)
            rules.Add(AuthDirectRule(serviceProcessPath, auth));
        rules.Add(new JsonObject { ["process_path_regex"] = Strings(patterns), ["ip_version"] = 6, ["outbound"] = "block" });
        rules.Add(new JsonObject { ["process_path_regex"] = Strings(patterns), ["outbound"] = "proxy" });
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
            AuthDirectRule(serviceProcessPath, auth).WriteTo(writer);
            if (previous.ValueKind == JsonValueKind.Array)
                foreach (var rule in previous.EnumerateArray())
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
