using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using WinClient.Core.Auth;
using WinClient.Core.Logging;

namespace WinClient.Core.Pairing;

public sealed class PairingFile
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    public string RawJson { get; }
    public NodeInfo Node { get; }
    public string DisplayName { get; }

    private PairingFile(string rawJson, NodeInfo node, string displayName)
    { RawJson = rawJson; Node = node; DisplayName = displayName; }

    public static PairingFile Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("format", out var format) ||
                format.ValueKind != JsonValueKind.String || format.GetString() != "ycpair/1")
                throw new InvalidDataException("配对文件版本不正确，请重新导出。");
            if (!root.TryGetProperty("node", out var nodeElement) || nodeElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("配对文件缺少出口信息。");
            var node = nodeElement.Deserialize<NodeInfo>(Json) ?? throw new InvalidDataException("配对文件缺少出口信息。");
            if (node.Host is null || !Regex.IsMatch(node.Host, @"\A[0-9]{1,3}(\.[0-9]{1,3}){3}\z") ||
                !IPAddress.TryParse(node.Host, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != node.Host)
                throw new InvalidDataException("出口地址必须是四段数字地址。");
            if (node.RealityPort is < 1 or > 65535 || node.Hy2Port is < 1 or > 65535)
                throw new InvalidDataException("出口端口必须在 1 到 65535 之间。");
            if (node.RealityPublicKey is null || !Regex.IsMatch(node.RealityPublicKey, @"\A[A-Za-z0-9_-]{43}\z"))
                throw new InvalidDataException("配对公钥格式不正确。");
            if (node.ShortId is null || !Regex.IsMatch(node.ShortId, @"\A[0-9A-Fa-f]{2,16}\z"))
                throw new InvalidDataException("配对短标识格式不正确。");
            if (node.Uuid is null || !Regex.IsMatch(node.Uuid, @"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z"))
                throw new InvalidDataException("设备标识必须是第四版设备唯一标识。");
            if (string.IsNullOrEmpty(node.Hy2Password)) throw new InvalidDataException("配对密码不能为空。");
            if (string.IsNullOrWhiteSpace(node.Sni)) throw new InvalidDataException("配对文件缺少连接校验名称。");
            var label = Text(root, "device_name") ?? Text(root, "exported_at") ?? "未注明导出时间";
            return new(json, node, label);
        }
        catch (JsonException) { throw new InvalidDataException("配对文件格式不正确或缺少必填字段，请重新导出。"); }
    }

    public void RegisterSecrets(RedactingLog log)
    {
        log.RegisterSecret(Node.Uuid);
        log.RegisterSecret(Node.Hy2Password);
    }

    private static string? Text(JsonElement root, string key) =>
        root.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString() : null;
}
