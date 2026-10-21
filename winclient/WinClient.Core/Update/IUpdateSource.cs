using System.Text.Json;
using System.Text.RegularExpressions;

namespace WinClient.Core.Update;

public sealed record UpdateIndex(string Version, string File, string Manifest, string Signature, long Size, string Sha256)
{
    public static UpdateIndex Parse(byte[] raw)
    {
        try
        {
            using var json = JsonDocument.Parse(raw);
            var root = json.RootElement;
            string Text(string name) => root.GetProperty(name).GetString() ?? throw new InvalidDataException();
            var version = new UpdateVersion(Text("version")).Value;
            var value = new UpdateIndex(version, Text("file"), Text("manifest"), Text("signature"), root.GetProperty("size").GetInt64(), Text("sha256"));
            if (value.File != $"YuanC-Client-{version}.exe" || value.Manifest != $"YuanC-Client-{version}.manifest.json" || value.Signature != value.Manifest + ".sig" ||
                value.Size < 0 || value.Size > UpdateManifest.MaxPayloadBytes || !Regex.IsMatch(value.Sha256, @"\A[0-9a-f]{64}\z")) throw new InvalidDataException();
            return value;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or InvalidDataException or OverflowException)
        { throw new InvalidDataException("更新目录格式不正确，未安装。"); }
    }
    public void Match(UpdateManifest manifest)
    {
        if (Version != manifest.Version || File != manifest.File || Size != manifest.Size || Sha256 != manifest.Sha256)
            throw new InvalidDataException("更新目录与签名清单不一致，未安装。");
    }
}

public interface IUpdateSource
{
    Task<UpdateIndex?> LatestAsync(CancellationToken token);
    Task<byte[]> ReadAsync(string name, int maximumBytes, CancellationToken token);
    Task DownloadAsync(UpdateManifest manifest, string temporaryFile, CancellationToken token);
}
