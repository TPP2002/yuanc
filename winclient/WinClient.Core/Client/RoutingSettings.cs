using System.Text.Json;

namespace WinClient.Core.Client;

public enum RoutingMode { Global, Apps }

public sealed record RoutingPolicy(RoutingMode Mode, IReadOnlyList<string> Apps)
{
    public static RoutingPolicy Global => new(RoutingMode.Global, []);

    public static RoutingPolicy Create(string mode, IEnumerable<string> apps)
    {
        var parsed = mode?.ToLowerInvariant() switch
        {
            "global" => RoutingMode.Global,
            "apps" => RoutingMode.Apps,
            _ => throw new ArgumentException("代理范围只能是全部流量或仅指定程序。")
        };
        var paths = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in apps)
        {
            var path = value?.Trim();
            if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path) ||
                !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.Length > 260 ||
                path.Any(char.IsControl) || path.Split(['\\', '/']).Contains("..", StringComparer.Ordinal))
                throw new ArgumentException("程序路径必须是以 .exe 结尾的完整路径。");
            if (seen.Add(path)) paths.Add(path);
            if (paths.Count > 32) throw new ArgumentException("最多选择 32 个程序。");
        }
        return new(parsed, paths.ToArray());
    }
}

public interface IRoutingSettingsStore
{
    RoutingPolicy Read();
    void Write(RoutingPolicy policy);
}

public sealed class RoutingSettingsStore(string? runRoot = null) : IRoutingSettingsStore
{
    private readonly string path = Path.Combine(runRoot ?? Path.Combine(ClientSettings.DataDirectory, "run"), "routing.json");
    private readonly object gate = new();

    public RoutingPolicy Read()
    {
        lock (gate)
        {
            try
            {
                using var json = JsonDocument.Parse(File.ReadAllText(path));
                var root = json.RootElement;
                return RoutingPolicy.Create(root.GetProperty("mode").GetString()!,
                    root.GetProperty("apps").EnumerateArray().Select(item => item.GetString()!));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or
                InvalidOperationException or ArgumentException or KeyNotFoundException)
            { return RoutingPolicy.Global; }
        }
    }

    public void Write(RoutingPolicy policy)
    {
        var mode = policy.Mode switch
        {
            RoutingMode.Global => "global", RoutingMode.Apps => "apps",
            _ => throw new ArgumentException("代理范围只能是全部流量或仅指定程序。")
        };
        var valid = RoutingPolicy.Create(mode, policy.Apps);
        lock (gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temporary = path + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, new { mode, apps = valid.Apps });
                    stream.Flush(true);
                }
                File.Move(temporary, path, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
