using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using WinClient.Core.Client;

namespace WinClient.Core.Kernel;

public interface IKernelInstaller
{
    string Ensure();
}

public interface IKernelSource
{
    string ManifestJson { get; }
    Stream Open(string logicalName);
}

public sealed class KernelInstaller(IKernelSource source, string? programDataRoot = null) : IKernelInstaller
{
    public const string VerificationFailureMessage = "连接内核文件校验失败,请重新安装客户端";
    private readonly object gate = new();

    public string Ensure()
    {
        lock (gate)
        {
            var manifest = ReadManifest();
            var root = programDataRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var directory = Path.GetFullPath(Path.Combine(root, ClientSettings.ProductName, "bin", manifest.Version));
            Directory.CreateDirectory(directory);
            foreach (var file in manifest.Files)
            {
                var destination = Path.Combine(directory, file.File);
                if (File.Exists(destination) && Matches(destination, file.Sha256)) continue;
                var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var input = source.Open(file.Resource))
                    using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        input.CopyTo(output);
                        output.Flush(flushToDisk: true);
                    }
                    File.Move(temporary, destination, overwrite: true);
                    if (!Matches(destination, file.Sha256))
                    {
                        File.Delete(destination);
                        throw new InvalidOperationException(VerificationFailureMessage);
                    }
                }
                finally
                {
                    if (File.Exists(temporary)) File.Delete(temporary);
                }
            }
            return Path.Combine(directory, "sing-box.exe");
        }
    }

    private Manifest ReadManifest()
    {
        Manifest? manifest;
        try { manifest = JsonSerializer.Deserialize<Manifest>(source.ManifestJson, new JsonSerializerOptions(JsonSerializerDefaults.Web)); }
        catch (JsonException ex) { throw new InvalidOperationException(VerificationFailureMessage, ex); }
        if (manifest is null || manifest.Version is null ||
            !Regex.IsMatch(manifest.Version, @"\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\z") ||
            manifest.Files is null || manifest.Files.Length != 2 ||
            manifest.Files.Any(file => file is null || file.File is not ("sing-box.exe" or "wintun.dll") ||
                file.Resource != "YuanC.Kernel." + file.File || file.Sha256 is null ||
                !Regex.IsMatch(file.Sha256, @"\A[0-9a-f]{64}\z")) ||
            manifest.Files.Select(file => file.File).Distinct(StringComparer.Ordinal).Count() != 2)
            throw new InvalidOperationException(VerificationFailureMessage);
        return manifest;
    }

    private static bool Matches(string path, string expected)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private sealed record Manifest(string Version, KernelFile[] Files);
    private sealed record KernelFile(string File, string Sha256, string Resource);
}
