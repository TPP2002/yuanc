using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WinClient.Core.Update;

public sealed record UpdateManifest(string Product, string Version, string File, string Sha256,
    long Size, DateTimeOffset BuiltAt, string MinServiceVersion)
{
    // 负责人 2026-11-27 定:安装包大小不设硬上限。这里只留 1 GiB 防呆线,免得坏掉的下载无限写盘。
    public const long MaxPayloadBytes = 1024L * 1024 * 1024;
    public static UpdateManifest Parse(byte[] bytes)
    {
        try
        {
            if (bytes.Length > 65536) throw new InvalidDataException();
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Select(p => p.Name).Distinct().Count() != root.EnumerateObject().Count())
                throw new InvalidDataException();
            string Text(string name) => root.GetProperty(name).GetString() ?? throw new InvalidDataException();
            var product = Text("product"); var version = Text("version"); var file = Text("file");
            var hash = Text("sha256"); var size = root.GetProperty("size").GetInt64();
            var built = Text("built_at"); var minimum = Text("min_service_version");
            _ = new UpdateVersion(version); _ = new UpdateVersion(minimum);
            if (product != "YuanC-Client" || file != $"YuanC-Client-{version}.exe" ||
                !Regex.IsMatch(hash, @"\A[0-9a-f]{64}\z") || size < 0 || size > MaxPayloadBytes ||
                !Regex.IsMatch(built, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})\z") ||
                !DateTimeOffset.TryParse(built, CultureInfo.InvariantCulture, DateTimeStyles.None, out var at))
                throw new InvalidDataException();
            return new(product, version, file, hash, size, at, minimum);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or InvalidDataException or OverflowException)
        { throw new InvalidDataException("更新清单格式不正确，未安装。"); }
    }
}
