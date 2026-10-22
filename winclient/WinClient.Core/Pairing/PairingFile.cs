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
    public string? Warning { get; }

    private PairingFile(string rawJson, NodeInfo node, string displayName, string? warning)
    { RawJson = rawJson; Node = node; DisplayName = displayName; Warning = warning; }

    public static PairingFile Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("format", out var format) ||
                format.ValueKind != JsonValueKind.String || format.GetString() is not ("ycpair/1" or "ycpair/2" or "ycpair/3"))
                throw new InvalidDataException("配对文件版本不正确，请重新导出。");
            if (!root.TryGetProperty("node", out var nodeElement) || nodeElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("配对文件缺少出口信息。");
            var version = format.GetString();
            bool isV3 = version == "ycpair/3";
            // v3 must carry the obfuscation password; v1/v2 are checked by the same rule only when the key is present.
            if (isV3 || nodeElement.TryGetProperty("hy2_obfs_password", out _))
                ValidateObfs(nodeElement);
            if (nodeElement.TryGetProperty("time_zone", out var timeZone) &&
                (timeZone.ValueKind != JsonValueKind.String ||
                 !Regex.IsMatch(timeZone.GetString()!, @"\A[A-Za-z0-9 ._+/()-]{1,64}\z")))
                throw new InvalidDataException("配对文件的时区标识格式不正确,请重新导出。");
            if (nodeElement.TryGetProperty("country", out var country) &&
                (country.ValueKind != JsonValueKind.String ||
                 !Regex.IsMatch(country.GetString()!, @"\A[A-Z]{2}\z")))
                throw new InvalidDataException("配对文件的国家码格式不正确,请重新导出。");
            var node = nodeElement.Deserialize<NodeInfo>(Json) ?? throw new InvalidDataException("配对文件缺少出口信息。");
            bool isV2 = version == "ycpair/2";
            if (isV2 || isV3 || nodeElement.TryGetProperty("hy2_server_name", out _) || nodeElement.TryGetProperty("hy2_certificate", out _))
                ValidateBackup(nodeElement, node);
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
            var warning = version switch
            {
                "ycpair/3" => null,
                "ycpair/2" => "配对文件是旧版,没有备用线路混淆参数;节点已启用混淆时备用线路不可用,建议在小主机上重新导出",
                _ => "配对文件是旧版,备用线路可能不可用,建议在小主机上重新导出"
            };
            return new(json, node, label, warning);
        }
        catch (JsonException) { throw new InvalidDataException("配对文件格式不正确或缺少必填字段，请重新导出。"); }
    }

    public void RegisterSecrets(RedactingLog log)
    {
        log.RegisterSecret(Node.Uuid);
        log.RegisterSecret(Node.Hy2Password);
        if (!string.IsNullOrEmpty(Node.Hy2ObfsPassword)) log.RegisterSecret(Node.Hy2ObfsPassword);
    }

    private static void ValidateObfs(JsonElement element)
    {
        if (!element.TryGetProperty("hy2_obfs_password", out var obfs) || obfs.ValueKind != JsonValueKind.String ||
            obfs.GetString() is not { } value || !Regex.IsMatch(value, @"\A[A-Za-z0-9_-]{16,128}\z"))
            throw new InvalidDataException("备用线路混淆密码格式不正确，请重新导出。");
    }

    private static void ValidateBackup(JsonElement element, NodeInfo node)
    {
        if (!element.TryGetProperty("hy2_server_name", out var name) || name.ValueKind != JsonValueKind.String ||
            node.Hy2ServerName is null || node.Hy2ServerName.Length > 253 ||
            !Regex.IsMatch(node.Hy2ServerName, @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z"))
            throw new InvalidDataException("备用线路证书名称必须是合法主机名。");
        if (!element.TryGetProperty("hy2_certificate", out var certificate) || certificate.ValueKind != JsonValueKind.Array ||
            node.Hy2Certificate is null || node.Hy2Certificate.Length < 3 || node.Hy2Certificate.Any(string.IsNullOrWhiteSpace) ||
            node.Hy2Certificate.Any(line => line.Contains('\n') || line.Contains('\r')) ||
            node.Hy2Certificate[0] != "-----BEGIN CERTIFICATE-----" || node.Hy2Certificate[^1] != "-----END CERTIFICATE-----")
            throw new InvalidDataException("备用线路证书必须为非空的逐行文本，并含正确的证书起止标记。");
    }

    private static string? Text(JsonElement root, string key) =>
        root.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString() : null;
}
