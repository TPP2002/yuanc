using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Client;

namespace WinClient.Core.EnvironmentSupport;

public sealed record EnvironmentPolicy(bool Enabled, EnvironmentTarget Target);
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
            json["languages"]?.AsArray().Select(item => item?.GetValue<string>() ?? throw new JsonException()).ToArray() ?? throw new JsonException()));

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
                ["enabled"] = true, ["time_zone"] = Default.Target.TimeZoneId,
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
