using System.Security.Cryptography;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Kernel;
using Xunit;

namespace WinClient.Tests;

public sealed class KernelInstallerTests
{
    [Fact]
    public void FirstRunWritesBothFilesAndReturnsFullExecutablePath()
    {
        using var directory = new TempDirectory();
        var source = new FakeSource();
        var result = new KernelInstaller(source, directory.Path).Ensure();
        Assert.Equal(Path.Combine(directory.Path, "YuanC", "bin", "1.10.7", "sing-box.exe"), result);
        Assert.True(Path.IsPathFullyQualified(result));
        AssertFiles(source, Path.GetDirectoryName(result)!);
        Assert.Equal(2, source.OpenCount);
        Assert.Empty(Directory.GetFiles(directory.Path, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    public void SecondRunDoesNotOpenResourcesOrRewriteEitherFile()
    {
        using var directory = new TempDirectory();
        var source = new FakeSource();
        var installer = new KernelInstaller(source, directory.Path);
        var path = installer.Ensure();
        var files = Directory.GetFiles(Path.GetDirectoryName(path)!);
        var timestamp = new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc);
        foreach (var file in files) File.SetLastWriteTimeUtc(file, timestamp);
        source.RejectOpens = true;
        Assert.Equal(path, installer.Ensure());
        Assert.Equal(2, source.OpenCount);
        Assert.All(files, file => Assert.Equal(timestamp, File.GetLastWriteTimeUtc(file)));
        AssertFiles(source, Path.GetDirectoryName(path)!);
    }

    [Fact]
    public void TamperingOneByteRepairsOnlyTheDamagedFile()
    {
        using var directory = new TempDirectory();
        var source = new FakeSource();
        var installer = new KernelInstaller(source, directory.Path);
        var path = installer.Ensure();
        var dll = Path.Combine(Path.GetDirectoryName(path)!, "wintun.dll");
        var timestamp = new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(dll, timestamp);
        var data = File.ReadAllBytes(path); data[0] ^= 1; File.WriteAllBytes(path, data);
        Assert.Equal(path, installer.Ensure());
        Assert.Equal(3, source.OpenCount);
        Assert.Equal(timestamp, File.GetLastWriteTimeUtc(dll));
        AssertFiles(source, Path.GetDirectoryName(path)!);
    }

    [Theory]
    [InlineData("sing-box.exe")]
    [InlineData("wintun.dll")]
    public void BadSourceHashThrowsChineseErrorAndLeavesNoBadFileOrTemporaryFile(string damagedFile)
    {
        using var directory = new TempDirectory();
        var source = new FakeSource { DamagedFile = damagedFile };
        var exception = Assert.Throws<InvalidOperationException>(() => new KernelInstaller(source, directory.Path).Ensure());
        Assert.Equal("连接内核文件校验失败,请重新安装客户端", exception.Message);
        Assert.False(File.Exists(Path.Combine(directory.Path, "YuanC", "bin", "1.10.7", damagedFile)));
        Assert.Empty(Directory.GetFiles(directory.Path, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    public void DifferentKernelVersionsHaveSeparateDirectories()
    {
        using var directory = new TempDirectory();
        var first = new KernelInstaller(new FakeSource(), directory.Path).Ensure();
        var second = new KernelInstaller(new FakeSource("1.10.8"), directory.Path).Ensure();
        Assert.NotEqual(Path.GetDirectoryName(first), Path.GetDirectoryName(second));
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
        Assert.Equal("1.10.8", new DirectoryInfo(Path.GetDirectoryName(second)!).Name);
    }

    [Fact]
    public void SourceReadFailureCleansTemporaryFile()
    {
        using var directory = new TempDirectory();
        var source = new FakeSource { RejectOpens = true };
        Assert.Throws<IOException>(() => new KernelInstaller(source, directory.Path).Ensure());
        Assert.Empty(Directory.GetFiles(directory.Path, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    public void ManifestCannotWriteOutsideVersionDirectory()
    {
        using var directory = new TempDirectory();
        var source = new FakeSource("../outside");
        Assert.Equal(KernelInstaller.VerificationFailureMessage,
            Assert.Throws<InvalidOperationException>(() => new KernelInstaller(source, directory.Path).Ensure()).Message);
        Assert.Equal(0, source.OpenCount);
        Assert.Empty(Directory.GetFiles(directory.Path, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void ServerSettingsAllowOmittedKernelPathAndPreserveExplicitPath()
    {
        using var directory = new TempDirectory();
        var configPath = Path.Combine(directory.Path, "server.json");
        File.WriteAllText(configPath, "{\"server_url\":\"https://192.0.2.1\"}");
        Assert.Null(ClientSettings.Load(directory.Path, kernelRoot: directory.Path)!.SingBoxPath);
        var explicitPath = Path.Combine(directory.Path, "custom", "sing-box.exe");
        File.WriteAllText(configPath, JsonSerializer.Serialize(new { server_url = "https://192.0.2.1", sing_box_path = explicitPath }));
        Assert.Equal(explicitPath, ClientSettings.Load(directory.Path, kernelRoot: directory.Path)!.SingBoxPath);
        File.WriteAllText(configPath, "{\"server_url\":\"https://192.0.2.1\",\"sing_box_path\":\"relative.exe\"}");
        Assert.Throws<InvalidDataException>(() => ClientSettings.Load(directory.Path, kernelRoot: directory.Path));
    }

    private static void AssertFiles(FakeSource source, string directory)
    {
        foreach (var (file, bytes) in source.Files)
            Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(directory, file)));
    }

    private sealed class FakeSource(string version = "1.10.7") : IKernelSource
    {
        public Dictionary<string, byte[]> Files { get; } = new()
        {
            ["sing-box.exe"] = [10, 20, 30, 40],
            ["wintun.dll"] = [50, 60, 70, 80]
        };
        public int OpenCount { get; private set; }
        public bool RejectOpens { get; set; }
        public string? DamagedFile { get; init; }
        public string ManifestJson => JsonSerializer.Serialize(new
        {
            version,
            files = Files.Select(pair => new
            {
                file = pair.Key,
                sha256 = Convert.ToHexString(SHA256.HashData(pair.Value)).ToLowerInvariant(),
                resource = "YuanC.Kernel." + pair.Key
            })
        });
        public Stream Open(string logicalName)
        {
            if (RejectOpens) throw new IOException("Resource should not be opened.");
            OpenCount++;
            var file = logicalName["YuanC.Kernel.".Length..];
            var bytes = Files[file].ToArray();
            if (file == DamagedFile) bytes[0] ^= 1;
            return new MemoryStream(bytes, writable: false);
        }
    }
}
