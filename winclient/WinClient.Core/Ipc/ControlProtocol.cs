using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinClient.Core.Client;

namespace WinClient.Core.Ipc;

public sealed record ControlRequest(long Id, string Op, string? Code = null, string? PairingJson = null);
public sealed record ControlResponse(long? Id, bool Ok, string? Error = null, ClientSnapshot? Snapshot = null, string? Audit = null);
public sealed record SnapshotEvent(string Event, ClientSnapshot Snapshot);

public static class ControlProtocol
{
    public const int MaxLineBytes = 1024 * 1024;
    internal static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Encode<T>(T message) => JsonSerializer.Serialize(message, Options) + "\n";
    public static ControlRequest DecodeRequest(string line)
    {
        using var json = JsonDocument.Parse(line);
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("id", out var id) ||
            !id.TryGetInt64(out _) || !root.TryGetProperty("op", out var op) || op.ValueKind != JsonValueKind.String)
            throw new JsonException();
        return JsonSerializer.Deserialize<ControlRequest>(line, Options) ?? throw new JsonException();
    }
    public static ControlResponse DecodeResponse(string line) => JsonSerializer.Deserialize<ControlResponse>(line, Options) ?? throw new JsonException();
    internal static SnapshotEvent DecodeEvent(string line) => JsonSerializer.Deserialize<SnapshotEvent>(line, Options) ?? throw new JsonException();
    internal static async Task WriteAsync<T>(Stream stream, T message, CancellationToken token)
    {
        var bytes = Utf8.GetBytes(Encode(message));
        if (bytes.Length - 1 > MaxLineBytes) throw new InvalidDataException("指令内容过长。");
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }
}

// Bounded byte framing: StreamReader.ReadLine would allocate an unbounded line before checking it.
internal sealed class ControlLineReader(Stream stream)
{
    private readonly byte[] buffer = new byte[4096];
    private int position;
    private int count;
    public async Task<string?> ReadAsync(CancellationToken token)
    {
        using var line = new MemoryStream();
        while (true)
        {
            if (position == count)
            {
                count = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
                position = 0;
                if (count == 0) return null; // An incomplete final frame is never executed.
            }
            var end = Array.IndexOf(buffer, (byte)'\n', position, count - position);
            var length = (end < 0 ? count : end) - position;
            if (line.Length + length > ControlProtocol.MaxLineBytes) throw new InvalidDataException("指令内容过长。");
            line.Write(buffer, position, length);
            position += length;
            if (end < 0) continue;
            position++;
            return ControlProtocol.Utf8.GetString(line.GetBuffer(), 0, (int)line.Length);
        }
    }
}
