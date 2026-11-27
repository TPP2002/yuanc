using System.Diagnostics;
using WinClient.Core.Client;
using WinClient.Core.Process;
using Xunit;

namespace WinClient.Tests;

public sealed class KernelLifetimeTests
{
    private static ProcessStartInfo PingStartInfo()
    {
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true
        };
        info.ArgumentList.Add("-n");
        info.ArgumentList.Add("60");
        info.ArgumentList.Add("127.0.0.1");
        return info;
    }

    private static ProcessStartInfo HiddenPing(string fileName)
    {
        var info = new ProcessStartInfo { FileName = fileName, CreateNoWindow = true, UseShellExecute = false };
        info.ArgumentList.Add("-n");
        info.ArgumentList.Add("60");
        info.ArgumentList.Add("127.0.0.1");
        return info;
    }

    private static System.Diagnostics.Process StartProcess(ProcessStartInfo info) => System.Diagnostics.Process.Start(info)!;

    private static void KillQuietly(System.Diagnostics.Process? process)
    {
        if (process is null) return;
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        process.Dispose();
    }

    [Fact]
    public void JobKillsChildWhenHandleCloses()
    {
        if (!OperatingSystem.IsWindows()) return;
        var process = StartProcess(PingStartInfo());
        try
        {
            using var job = KernelJob.Create();
            job.Assign(process);
            Assert.True(job.Contains(process));
            job.Dispose();
            Assert.True(process.WaitForExit(5000));
        }
        finally { KillQuietly(process); }
    }

    [Fact]
    public void LauncherPutsKernelInSharedJob()
    {
        if (!OperatingSystem.IsWindows()) return;
        ISingBoxProcess? started = null;
        try
        {
            started = new SingBoxLauncher().Start(PingStartInfo(), _ => { }, _ => { });
            var child = Assert.IsType<SingBoxLauncher.Child>(started);
            Assert.NotNull(SingBoxLauncher.SharedJob);
            Assert.True(SingBoxLauncher.SharedJob!.Contains(child.Process));
        }
        finally { started?.Stop(); started?.Dispose(); }
    }

    [Fact]
    public void SweeperKillsSamePathCopyOnly()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var directory = new TempDirectory();
        var firstDirectory = Path.Combine(directory.Path, "a");
        var secondDirectory = Path.Combine(directory.Path, "b");
        Directory.CreateDirectory(firstDirectory);
        Directory.CreateDirectory(secondDirectory);
        var source = Path.Combine(Environment.SystemDirectory, "PING.EXE");
        var firstExe = Path.Combine(firstDirectory, "sing-box.exe");
        var secondExe = Path.Combine(secondDirectory, "sing-box.exe");
        File.Copy(source, firstExe);
        File.Copy(source, secondExe);
        var first = StartProcess(HiddenPing(firstExe));
        var second = StartProcess(HiddenPing(secondExe));
        try
        {
            Thread.Sleep(300);
            Assert.False(first.HasExited);
            Assert.False(second.HasExited);
            Assert.Equal(1, new StrayKernelSweeper().Sweep(firstExe, null));
            Assert.True(first.WaitForExit(5000));
            Assert.False(second.HasExited);
        }
        finally { KillQuietly(first); KillQuietly(second); }
    }

    [Fact]
    public void SweeperMatchesOwnedBinDirectoryOnly()
    {
        using var directory = new TempDirectory();
        var product = Path.Combine(directory.Path, "YuanC");
        var owned = Path.Combine(product, "bin");
        var table = new FakeTable();
        table.Processes.Add(new(101, Path.Combine(owned, "1.13.21", "sing-box.exe")));
        table.Processes.Add(new(102, Path.Combine(product, "other", "sing-box.exe")));
        table.Processes.Add(new(103, Path.Combine(owned, "1.13.21", "wintun.dll")));
        table.Processes.Add(new(104, Path.Combine(product, "bin2", "sing-box.exe")));
        var lines = new List<string>();
        var stopped = new StrayKernelSweeper(table).Sweep(Path.Combine(owned, "9.9.9", "sing-box.exe"), owned, lines.Add);
        Assert.Equal(1, stopped);
        Assert.Equal(new[] { 101 }, table.Killed);
        Assert.Contains("已结束上次残留的连接内核 1 个。", lines);
    }

    [Fact]
    public void SweeperSkipsSelfAndUnreadablePaths()
    {
        using var directory = new TempDirectory();
        var owned = Path.Combine(directory.Path, "YuanC", "bin");
        var executable = Path.Combine(owned, "sing-box.exe");
        var table = new FakeTable();
        table.Processes.Add(new(Environment.ProcessId, executable));
        table.Processes.Add(new(202, null));
        Assert.Equal(0, new StrayKernelSweeper(table).Sweep(executable, owned));
        Assert.Empty(table.Killed);
    }

    [Fact]
    public void SweeperThrowsWhenStrayWillNotExit()
    {
        using var directory = new TempDirectory();
        var owned = Path.Combine(directory.Path, "YuanC", "bin");
        var executable = Path.Combine(owned, "sing-box.exe");
        var table = new FakeTable();
        table.Processes.Add(new(301, executable));
        table.Processes.Add(new(302, executable));
        table.Refuse.Add(301);
        var lines = new List<string>();
        var error = Assert.Throws<IOException>(() => new StrayKernelSweeper(table).Sweep(executable, owned, lines.Add));
        Assert.Equal(StrayKernelSweeper.NotStoppedMessage, error.Message);
        Assert.Equal(new[] { 301, 302 }, table.Killed);
        Assert.Contains("已结束上次残留的连接内核 1 个。", lines);
    }

    [Fact]
    public void ManagerSweepsBeforeEveryLaunch()
    {
        using var directory = new TempDirectory();
        var exe = Path.Combine(directory.Path, "fake.exe");
        File.WriteAllText(exe, "fake kernel fixture");
        var table = new FakeTable();
        var launcher = new RecordingLauncher(table);
        using var manager = new SingBoxProcessManager(exe, "YuanC", launcher, new AuthTests.MemoryLog(), directory.Path,
            new StrayKernelSweeper(table));
        manager.Start(TestData.Config);
        manager.Start(TestData.Config);
        Assert.Equal(2, launcher.LaunchCount);
        Assert.All(launcher.FindCallsAtLaunch, count => Assert.True(count > 0));
        table.Processes.Add(new(401, exe));
        table.Refuse.Add(401);
        Assert.Throws<IOException>(() => manager.Start(TestData.Config));
        Assert.Equal(2, launcher.LaunchCount);
        table.Refuse.Remove(401);
        Assert.Equal(1, manager.StopAndSweep());
    }

    [Fact]
    public async Task TransportWaitsForStaleAdapterBeforeLaunch()
    {
        using var directory = new TempDirectory();
        var launcher = new ScriptedLauncher();
        var probe = new ScriptedProbe(call => call != 2);
        var callsAtLaunch = -1;
        launcher.OnLaunch = () => callsAtLaunch = probe.Calls;
        using var manager = new SingBoxProcessManager(CreateExecutable(directory), "YuanC", launcher,
            new AuthTests.MemoryLog(), directory.Path, new StrayKernelSweeper(new FakeTable()));
        using var transport = new TunnelTransport(manager, probe.Read, (_, _) => Task.CompletedTask);
        await transport.StartAsync(TestData.Config, CancellationToken.None);
        Assert.Equal(1, launcher.LaunchCount);
        Assert.Equal(2, callsAtLaunch);
    }

    [Fact]
    public async Task TransportRequiresSettledChildWhenAdapterStayed()
    {
        using var stableDirectory = new TempDirectory();
        var stableLauncher = new ScriptedLauncher();
        var stableProbe = new ScriptedProbe(_ => true);
        using (var manager = new SingBoxProcessManager(CreateExecutable(stableDirectory), "YuanC", stableLauncher,
                   new AuthTests.MemoryLog(), stableDirectory.Path, new StrayKernelSweeper(new FakeTable())))
        using (var transport = new TunnelTransport(manager, stableProbe.Read, (_, _) => Task.CompletedTask))
            await transport.StartAsync(TestData.Config, CancellationToken.None);
        Assert.Equal(1, stableLauncher.LaunchCount);
        Assert.Equal(21 + 8, stableProbe.Calls);

        using var unstableDirectory = new TempDirectory();
        var unstableLauncher = new ScriptedLauncher();
        var unstableProbe = new ScriptedProbe(call => call <= 28);
        using (var manager = new SingBoxProcessManager(CreateExecutable(unstableDirectory), "YuanC", unstableLauncher,
                   new AuthTests.MemoryLog(), unstableDirectory.Path, new StrayKernelSweeper(new FakeTable())))
        using (var transport = new TunnelTransport(manager, unstableProbe.Read, (_, _) => Task.CompletedTask))
            await Assert.ThrowsAsync<TimeoutException>(() => transport.StartAsync(TestData.Config, CancellationToken.None));
        Assert.Equal(1, unstableLauncher.LaunchCount);
        Assert.Equal(21 + 40, unstableProbe.Calls);
    }

    [Fact]
    public async Task TransportFailsWhenKernelExitsDuringSettle()
    {
        using var directory = new TempDirectory();
        var launcher = new ScriptedLauncher();
        var launched = false;
        launcher.OnLaunch = () => launched = true;
        var probe = new ScriptedProbe(call =>
        {
            if (launched && call == 22) launcher.Exit?.Invoke(1);
            return true;
        });
        using var manager = new SingBoxProcessManager(CreateExecutable(directory), "YuanC", launcher,
            new AuthTests.MemoryLog(), directory.Path, new StrayKernelSweeper(new FakeTable()));
        using var transport = new TunnelTransport(manager, probe.Read, (_, _) => Task.CompletedTask);
        var error = await Assert.ThrowsAsync<IOException>(() => transport.StartAsync(TestData.Config, CancellationToken.None));
        Assert.Equal("连接内核在启动期间退出。", error.Message);
    }

    private static string CreateExecutable(TempDirectory directory)
    {
        var path = Path.Combine(directory.Path, "fake.exe");
        File.WriteAllText(path, "fake kernel fixture");
        return path;
    }

    private sealed class FakeTable : IKernelProcessTable
    {
        public List<KernelProcessInfo> Processes { get; } = [];
        public HashSet<int> Refuse { get; } = [];
        public List<int> Killed { get; } = [];
        public int FindCalls { get; private set; }

        public IReadOnlyList<KernelProcessInfo> FindByName(string processName)
        {
            FindCalls++;
            return Processes.ToList();
        }

        public bool Kill(int id, TimeSpan wait)
        {
            Killed.Add(id);
            if (Refuse.Contains(id)) return false;
            Processes.RemoveAll(process => process.Id == id);
            return true;
        }
    }

    private sealed class RecordingLauncher(FakeTable table) : ISingBoxLauncher
    {
        public int LaunchCount { get; private set; }
        public List<int> FindCallsAtLaunch { get; } = [];

        public ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit)
        {
            LaunchCount++;
            FindCallsAtLaunch.Add(table.FindCalls);
            return new Idle();
        }
    }

    private sealed class ScriptedLauncher : ISingBoxLauncher
    {
        public int LaunchCount { get; private set; }
        public Action? OnLaunch { get; set; }
        public Action<int>? Exit { get; private set; }

        public ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit)
        {
            LaunchCount++;
            Exit = onExit;
            OnLaunch?.Invoke();
            return new Idle();
        }
    }

    private sealed class Idle : ISingBoxProcess
    {
        public void Stop() { }
        public void Dispose() { }
    }

    private sealed class ScriptedProbe(Func<int, bool> script)
    {
        public int Calls { get; private set; }

        public bool Read()
        {
            Calls++;
            return script(Calls);
        }
    }
}
