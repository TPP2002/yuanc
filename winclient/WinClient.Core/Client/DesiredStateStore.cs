using System.Text.Json;

namespace WinClient.Core.Client;

public sealed class DesiredStateStore(string? runRoot = null)
{
    private readonly string path = Path.Combine(runRoot ?? Path.Combine(ClientSettings.DataDirectory, "run"), "desired.json");
    private readonly object gate = new();

    public bool? Read()
    {
        lock (gate)
        {
            try
            {
                using var json = JsonDocument.Parse(File.ReadAllText(path));
                return json.RootElement.GetProperty("connect").GetBoolean();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or KeyNotFoundException)
            { return null; }
        }
    }

    public void Write(bool connect)
    {
        lock (gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temporary = path + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, new { connect, updated_at = DateTimeOffset.UtcNow.ToString("O") });
                    stream.Flush(true);
                }
                File.Move(temporary, path, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
