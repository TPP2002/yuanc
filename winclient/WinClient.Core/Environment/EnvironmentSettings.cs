using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using WinClient.Core.Auth;
using WinClient.Core.Client;

namespace WinClient.Core.EnvironmentSupport;

public sealed record EnvironmentPolicy(bool Enabled, EnvironmentTarget Target, string ExpectedCountry = "AU");

public static class EnvironmentPolicyExtensions
{
    public static EnvironmentPolicy ForNode(this EnvironmentPolicy policy, NodeInfo? node)
    {
        if (node is null || (string.IsNullOrEmpty(node.TimeZone) && string.IsNullOrEmpty(node.Country))) return policy;
        var target = policy.Target;
        var tz = node.TimeZone;
        if (!string.IsNullOrEmpty(tz) && Regex.IsMatch(tz, @"\A[A-Za-z0-9 ._+/()-]{1,64}\z"))
        {
            string? resolved = null;
            if (TimeZoneInfo.TryConvertIanaIdToWindowsId(tz, out var windowsId)) resolved = windowsId;
            else if (TimeZoneInfo.TryFindSystemTimeZoneById(tz, out _)) resolved = tz;
            // 下发值只参与解析；写入系统前仍须满足既有目标格式限制。
            if (resolved is not null && Regex.IsMatch(resolved, @"\A[A-Za-z0-9 .()+/-]{1,64}\z"))
                target = new EnvironmentTarget(resolved, policy.Target.Languages);
        }
        return policy with { Target = target, ExpectedCountry = string.IsNullOrEmpty(node.Country) ? policy.ExpectedCountry : node.Country };
    }
}

public interface IEnvironmentSettingsStore
{
    EnvironmentPolicy Read();
    void WriteEnabled(bool enabled);
}

public sealed class EnvironmentSettingsStore(string? runRoot = null) : IEnvironmentSettingsStore
{
    private readonly string path = Path.Combine(runRoot ?? Path.Combine(ClientSettings.DataDirectory, "run"), "environment.json");
    private readonly object gate = new();
    public static EnvironmentPolicy Default => new(true, new("AUS Eastern Standard Time", ["en-AU", "en"]));

    private static EnvironmentPolicy Parse(JsonObject json) => new(
        json["enabled"]?.GetValue<bool>() ?? throw new JsonException(),
        new(json["time_zone"]?.GetValue<string>() ?? throw new JsonException(),
            json["languages"]?.AsArray().Select(item => item?.GetValue<string>() ?? throw new JsonException()).ToArray() ?? throw new JsonException()),
        ParseCountry(json["country"]));

    private static string ParseCountry(JsonNode? value) => value is JsonValue json && json.TryGetValue<string>(out var country)
        && country is not null && country.Length == 2 && Regex.IsMatch(country, "^[A-Z]{2}$") ? country : "AU";

    private JsonObject? ReadObject()
    {
        try
        {
            var json = JsonNode.Parse(File.ReadAllText(path))?.AsObject() ?? throw new JsonException();
            _ = Parse(json);
            return json;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or ArgumentException or FormatException)
        { return null; }
    }

    public EnvironmentPolicy Read()
    {
        lock (gate) return ReadObject() is { } json ? Parse(json) : Default;
    }

    public void WriteEnabled(bool enabled)
    {
        lock (gate)
        {
            var json = ReadObject() ?? new JsonObject
            {
                ["enabled"] = true, ["time_zone"] = Default.Target.TimeZoneId, ["country"] = Default.ExpectedCountry,
                ["languages"] = new JsonArray(Default.Target.Languages.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray())
            };
            json["enabled"] = enabled;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temporary = path + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, json);
                    stream.Flush(true);
                }
                File.Move(temporary, path, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
