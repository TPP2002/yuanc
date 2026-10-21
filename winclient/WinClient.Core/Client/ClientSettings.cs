using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinClient.Core.Client;

public sealed class ClientSettings
{
    public const string ProductName = "YuanC";
    [JsonPropertyName("server_url")] public required string ServerUrl { get; init; }
    [JsonPropertyName("sing_box_path")] public string? SingBoxPath { get; init; }
    public static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ProductName);
    public static ClientSettings? Load(string? dataDirectory = null)
    {
        var path = Path.Combine(dataDirectory ?? DataDirectory, "server.json");
        if (!File.Exists(path)) return null;
        var settings = JsonSerializer.Deserialize<ClientSettings>(File.ReadAllText(path))
            ?? throw new InvalidDataException("服务器配置无效。");
        if (!Uri.TryCreate(settings.ServerUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidDataException("服务器必须配置为不含凭据的 HTTPS 地址。");
        if (settings.SingBoxPath is not null && !Path.IsPathFullyQualified(settings.SingBoxPath))
            throw new InvalidDataException("连接内核必须配置为绝对路径。");
        return settings;
    }

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
