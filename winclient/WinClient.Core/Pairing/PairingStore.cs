using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace WinClient.Core.Pairing;

[SupportedOSPlatform("windows")]
public sealed class PairingStore
{
    public string FilePath { get; }
    public bool Exists => File.Exists(FilePath);
    public PairingStore(string? localAppDataRoot = null)
    {
        FilePath = Path.Combine(localAppDataRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "YuanC", "pairing.bin");
    }

    public void Save(PairingFile pairing)
    {
        var plain = Encoding.UTF8.GetBytes(pairing.RawJson);
        try
        {
            var encrypted = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            var temporary = FilePath + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                { stream.Write(encrypted); stream.Flush(true); }
                File.Move(temporary, FilePath, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public PairingFile? Load()
    {
        if (!Exists) return null;
        var plain = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), null, DataProtectionScope.CurrentUser);
        try { return PairingFile.Parse(Encoding.UTF8.GetString(plain)); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public void Clear() { if (Exists) File.Delete(FilePath); }
}
