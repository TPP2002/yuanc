using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinClient.Core.Firewall;

namespace WinClient.Core.Client;

public sealed class ClientSettings
{
    public const string ProductName = "YuanC";
    [JsonPropertyName("server_url")] public required string ServerUrl { get; init; }
    [JsonPropertyName("server_spki_sha256")] public string? ServerSpkiSha256 { get; init; }
    [JsonPropertyName("sing_box_path")] public string? SingBoxPath { get; init; }
    [JsonIgnore] public AuthEndpoint? AuthEndpoint
    {
        get
        {
            if (Environment.ProcessPath is not { Length: > 0 } program) return null;
            var uri = new Uri(ServerUrl);
            return new(IPAddress.Parse(uri.Host), uri.Port, Path.GetFullPath(program));
        }
    }
    public static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ProductName);
    public static ClientSettings? Load(string? dataDirectory = null, Func<string, bool>? ownerIsTrusted = null, string? kernelRoot = null)
    {
        var path = Path.Combine(dataDirectory ?? DataDirectory, "server.json");
        if (!File.Exists(path)) return null;
        if (ownerIsTrusted is not null && !ownerIsTrusted(path))
            throw new InvalidDataException("服务器配置文件的所有者不是系统或管理员，已拒绝读取。");
        var settings = JsonSerializer.Deserialize<ClientSettings>(File.ReadAllText(path))
            ?? throw new InvalidDataException("服务器配置无效。");
        if (!Uri.TryCreate(settings.ServerUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidDataException("服务器必须配置为不含凭据的 HTTPS 地址。");
        if (uri.HostNameType != UriHostNameType.IPv4)
            throw new InvalidDataException("服务器地址必须是 IPv4 数字地址，不使用域名。");
        if (string.IsNullOrWhiteSpace(settings.ServerSpkiSha256) ||
            !Convert.TryFromBase64String(settings.ServerSpkiSha256, new byte[32], out var pinLength) || pinLength != 32)
            throw new InvalidDataException("服务器配置缺少有效的证书指纹 server_spki_sha256(证书公钥的 SHA-256,44 个字符的 base64),请按部署说明补上。");
        if (settings.SingBoxPath is not null && !Path.IsPathFullyQualified(settings.SingBoxPath))
            throw new InvalidDataException("连接内核必须配置为绝对路径。");
        if (!string.IsNullOrEmpty(settings.SingBoxPath))
        {
            var root = Path.GetFullPath(kernelRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), ProductName))
                .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var kernel = Path.GetFullPath(settings.SingBoxPath).Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
            if (!kernel.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                settings.SingBoxPath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar).Split(Path.DirectorySeparatorChar).Contains(".."))
                throw new InvalidDataException("连接内核必须位于程序安装目录之下。");
        }
        return settings;
    }

    public static string ComputeSpkiSha256(X509Certificate2 certificate) =>
        Convert.ToBase64String(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));

    internal static bool MatchesPin(X509Certificate2? certificate, string expectedBase64) =>
        certificate is not null && CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()), Convert.FromBase64String(expectedBase64));

    internal static Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> PinValidator(string expectedBase64) =>
        (_, cert, _, _) => MatchesPin(cert, expectedBase64);

    public HttpClient CreateAuthHttpClient() => new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = PinValidator(ServerSpkiSha256!)
    }) { BaseAddress = new Uri(ServerUrl), Timeout = TimeSpan.FromSeconds(15) };

    public static string GetDeviceFingerprint(string? root = null, DataProtectionScope scope = DataProtectionScope.CurrentUser)
    {
        var directory = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), ProductName);
        var path = Path.Combine(directory, "device-id");
        Directory.CreateDirectory(directory);
        // Preserve the original default user identity format; the service uses machine encryption.
        if (File.Exists(path))
        {
            if (scope == DataProtectionScope.CurrentUser) return File.ReadAllText(path).Trim();
            var decoded = ProtectedData.Unprotect(File.ReadAllBytes(path), null, scope);
            try { return System.Text.Encoding.UTF8.GetString(decoded); }
            finally { CryptographicOperations.ZeroMemory(decoded); }
        }
        var identity = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var plain = System.Text.Encoding.UTF8.GetBytes(identity);
        try
        {
            stream.Write(scope == DataProtectionScope.CurrentUser ? plain : ProtectedData.Protect(plain, null, scope));
            stream.Flush(true);
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
        return identity;
    }
}
