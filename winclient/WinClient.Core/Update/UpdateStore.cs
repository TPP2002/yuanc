using System.Text;
using System.Text.Json;
using WinClient.Core.Client;

namespace WinClient.Core.Update;

public sealed record UpdatePending(string OldExe, string OldVersion, string NewExe, string NewVersion, DateTimeOffset StartedAt);
public sealed record UpdateHistory(string Version, string Status, DateTimeOffset At, string? Reason = null);

public sealed class UpdateStore
{
    private readonly object gate = new();
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    public string Root { get; }
    public string Incoming => Path.Combine(Root, "incoming");
    public string PendingPath => Path.Combine(Root, "pending.json");
    public bool HasPending => File.Exists(PendingPath);
    public UpdateStore(string? root = null) => Root = Path.GetFullPath(root ?? Path.Combine(ClientSettings.DataDirectory, "updates"));

    public static void AtomicWrite(string path, byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        try
        {
            using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            { output.Write(bytes); output.Flush(true); }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private static void Validate(UpdatePending value)
    {
        _ = new UpdateVersion(value.OldVersion); _ = new UpdateVersion(value.NewVersion);
        foreach (var pair in new[] { (value.OldExe, value.OldVersion), (value.NewExe, value.NewVersion) })
            if (pair.Item1 is null || !Path.IsPathFullyQualified(pair.Item1) ||
                Path.GetFileName(pair.Item1) != "YuanC-Client.exe" || Path.GetFileName(Path.GetDirectoryName(pair.Item1)) != pair.Item2)
                throw new InvalidDataException("更新恢复记录不正确。");
        if (value.OldVersion == value.NewVersion || value.StartedAt == default) throw new InvalidDataException("更新恢复记录不正确。");
    }
    public UpdatePending? ReadPending()
    {
        lock (gate)
        {
            try
            {
                var value = JsonSerializer.Deserialize<UpdatePending>(File.ReadAllBytes(PendingPath), Json) ?? throw new InvalidDataException();
                Validate(value); return value;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidDataException)
            { return null; }
        }
    }
    public void WritePending(UpdatePending value)
    { Validate(value); lock (gate) AtomicWrite(PendingPath, JsonSerializer.SerializeToUtf8Bytes(value, Json)); }
    public void DeletePending() { lock (gate) File.Delete(PendingPath); }
    private string BadPath(string version) => Path.Combine(Root, new UpdateVersion(version) + ".bad");
    public bool IsBad(string version) => File.Exists(BadPath(version));
    public void MarkBad(string version) { lock (gate) AtomicWrite(BadPath(version), Encoding.UTF8.GetBytes("新版后台未能正常响应，请联系维护人员。")); }
    public void AppendHistory(string version, string status, DateTimeOffset at, string? reason = null)
    {
        _ = new UpdateVersion(version);
        if (status is not ("staged" or "ok" or "rolled_back" or "failed" or "skipped" or "needs_manual")) throw new ArgumentException("更新记录状态无效。");
        lock (gate)
        {
            var path = Path.Combine(Root, "history.jsonl");
            var old = File.Exists(path) ? File.ReadAllText(path) : "";
            AtomicWrite(path, Encoding.UTF8.GetBytes(old + JsonSerializer.Serialize(new UpdateHistory(version, status, at, reason), Json) + "\n"));
        }
    }
    public IReadOnlyList<UpdateHistory> ReadHistory()
    {
        lock (gate)
        {
            var path = Path.Combine(Root, "history.jsonl");
            if (!File.Exists(path)) return [];
            var result = new List<UpdateHistory>();
            foreach (var line in File.ReadLines(path))
            {
                try
                {
                    var value = JsonSerializer.Deserialize<UpdateHistory>(line, Json);
                    if (value is not null && value.At != default && value.Status is "staged" or "ok" or "rolled_back" or "failed" or "skipped" or "needs_manual")
                    { _ = new UpdateVersion(value.Version); result.Add(value); }
                }
                catch (Exception ex) when (ex is JsonException or InvalidDataException) { /* Preserve corrupt rows on disk. */ }
            }
            return result;
        }
    }
}
