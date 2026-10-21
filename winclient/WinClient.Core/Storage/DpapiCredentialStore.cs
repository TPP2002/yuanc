using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace WinClient.Core.Storage;

[SupportedOSPlatform("windows")]
public sealed class DpapiCredentialStore : ICredentialStore
{
    private readonly string path;
    public DpapiCredentialStore(string productName, string? localAppDataRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(productName);
        if (productName is "." or ".." || productName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || productName.Contains('/') || productName.Contains('\\'))
            throw new ArgumentException("产品名必须是单个目录名称。", nameof(productName));
        path = Path.Combine(localAppDataRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), productName, "credential.bin");
    }

    public void Save(string refreshToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);
        var plain = Encoding.UTF8.GetBytes(refreshToken);
        try
        {
            var encrypted = ProtectedData.Protect(plain, optionalEntropy: null, DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            try
            {
                using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                { stream.Write(encrypted); stream.Flush(true); }
                File.Move(temp, path, overwrite: true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public string? Load()
    {
        if (!File.Exists(path)) return null;
        var plain = ProtectedData.Unprotect(File.ReadAllBytes(path), optionalEntropy: null, DataProtectionScope.CurrentUser);
        try { return Encoding.UTF8.GetString(plain); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public void Clear() { if (File.Exists(path)) File.Delete(path); }
}
