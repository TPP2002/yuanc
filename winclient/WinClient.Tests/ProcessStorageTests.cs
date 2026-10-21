using System.Diagnostics;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Logging;
using WinClient.Core.Process;
using WinClient.Core.Storage;
using Xunit;

namespace WinClient.Tests;

public sealed class ProcessStorageTests
{
    [Fact]
    public void ProcessConfigIsAtomicAndLaunchHiddenAndExitReported()
    {
        using var directory = new TempDirectory();
        var exe = Path.Combine(directory.Path, "fake.exe"); File.WriteAllText(exe, "fake launcher fixture");
        var launcher = new Launcher(); var sink = new AuthTests.MemoryLog();
        using var manager = new SingBoxProcessManager(exe, "YuanC", launcher, sink, directory.Path);
        var exits = new List<int>(); manager.TunnelDown += (_, code) => exits.Add(code);
        var config = JsonSerializer.SerializeToElement(new { password = "secret-value", inbounds = new[] { new { type = "tun" } } });
        manager.Start(config);
        Assert.Equal(config.GetRawText(), File.ReadAllText(manager.ConfigPath));
        Assert.False(File.Exists(manager.ConfigPath + ".tmp"));
        Assert.True(launcher.Info.CreateNoWindow); Assert.False(launcher.Info.UseShellExecute);
        Assert.True(launcher.Info.RedirectStandardOutput); Assert.True(launcher.Info.RedirectStandardError);
        Assert.Equal(new[] { "run", "-c", manager.ConfigPath }, launcher.Info.ArgumentList);
        launcher.Log!("secret-value"); Assert.DoesNotContain("secret-value", string.Join("", sink.Lines));
        launcher.Exit!(7); Assert.Equal(new[] { 7 }, exits);
        manager.Stop(); launcher.Exit(0); Assert.Single(exits);
    }
    [Fact]
    public void MissingKernelGivesChineseError()
    {
        using var directory = new TempDirectory();
        using var manager = new SingBoxProcessManager(Path.Combine(directory.Path, "missing.exe"), "YuanC", new Launcher(), programDataRoot: directory.Path);
        Assert.Contains("未找到连接内核", Assert.Throws<FileNotFoundException>(() => manager.Start(TestData.Config)).Message);
    }
    [Fact]
    public void ConfigRenderingDoesNotModifyServerObject()
    {
        var original = TestData.Config;
        var result = TunnelTransport.RenderConfiguration(original);
        var inbound = result.GetProperty("inbounds")[0];
        Assert.Equal("YuanC-TUN", inbound.GetProperty("interface_name").GetString());
        Assert.True(inbound.GetProperty("strict_route").GetBoolean());
        Assert.True(inbound.GetProperty("auto_route").GetBoolean());
        Assert.False(original.GetProperty("inbounds")[0].TryGetProperty("interface_name", out _));
        Assert.Throws<InvalidDataException>(() => TunnelTransport.RenderConfiguration(JsonSerializer.SerializeToElement(new { })));
    }
    [Fact]
    public void MemoryStoreRoundTripsAndClears()
    {
        ICredentialStore store = new InMemoryCredentialStore();
        Assert.Null(store.Load()); store.Save("first"); Assert.Equal("first", store.Load());
        store.Save("second"); Assert.Equal("second", store.Load()); store.Clear(); Assert.Null(store.Load());
    }
    [Fact]
    public void DpapiStoresCiphertextAndDetectsCorruption()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var directory = new TempDirectory();
        var store = new DpapiCredentialStore("YuanC", directory.Path);
        store.Save("refresh-secret"); Assert.Equal("refresh-secret", store.Load());
        var path = Path.Combine(directory.Path, "YuanC", "credential.bin");
        Assert.DoesNotContain("refresh-secret", System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(path)));
        File.WriteAllText(path, "corrupt"); Assert.Throws<System.Security.Cryptography.CryptographicException>(() => store.Load());
        store.Clear(); Assert.Null(store.Load());
    }
    [Fact]
    public void RollingLogsAreBounded()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, "kernel.log");
        var log = new RollingFileLog(path, 1024, 2);
        for (var i = 0; i < 100; i++) log.Write(new string('x', 200));
        Assert.InRange(Directory.GetFiles(directory.Path).Length, 1, 3);
        Assert.All(Directory.GetFiles(directory.Path), file => Assert.True(new FileInfo(file).Length <= 1024));
    }
    [Fact]
    public void MissingServerHasNoDefaultAndIdentityIsStable()
    {
        using var directory = new TempDirectory();
        Assert.Null(ClientSettings.Load(directory.Path));
        Assert.Equal(ClientSettings.GetDeviceFingerprint(directory.Path), ClientSettings.GetDeviceFingerprint(directory.Path));
    }
    private sealed class Launcher : ISingBoxLauncher
    {
        public ProcessStartInfo Info { get; private set; } = new() { CreateNoWindow = true, UseShellExecute = false };
        public Action<int>? Exit { get; private set; }
        public Action<string>? Log { get; private set; }
        public ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit)
        { Info = startInfo; Exit = onExit; Log = onLog; return new Child(); }
        private sealed class Child : ISingBoxProcess { public void Stop() { } public void Dispose() { } }
    }
}
