using System.Diagnostics;
using WinClient.App.Hosting;
using WinClient.Core.Firewall;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.Logging;
using WinClient.Core.State;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.Tests;

public sealed class UpdateApplierTests
{
    [Theory]
    [InlineData("ok", false, false, "ok")]
    [InlineData("silent", false, true, "rolled_back")]
    [InlineData("wrong_version", false, true, "rolled_back")]
    [InlineData("network", false, false, "rolled_back")]
    [InlineData("silent", true, true, "needs_manual")]
    public async Task CommandsAndRecoveryBranches(string mode, bool rollbackFails, bool bad, string history)
    {
        using var temp = new TempDirectory();
        var root = Path.Combine(temp.Path, "app");
        var store = new UpdateStore(Path.Combine(temp.Path, "updates"));
        var host = new Host(mode);
        var pending = Pending(root, host.Now);
        store.WritePending(pending);
        var commands = new Runner(pending, rollbackFails);
        var applier = new UpdateApplier(store, commands, host, root, Path.GetFullPath("Windows/System32"));
        Assert.Equal(history == "ok" ? 0 : 1, await applier.RunAsync());
        Assert.Equal(history, store.ReadHistory().Last().Status);
        Assert.Equal(bad, store.IsBad("1.0.0"));
        Assert.Equal(history == "needs_manual", store.HasPending);
        Assert.Equal(ServiceInstaller.Stop(), commands.Commands[0]);
        Assert.Equal(ServiceInstaller.Configure(pending.NewExe, true), commands.Commands[1]);
        Assert.Equal(ServiceInstaller.Start(), commands.Commands[2]);
        if (history == "ok") Assert.Equal(pending.NewExe, host.RunExe);
        else
        {
            Assert.Equal(ServiceInstaller.Stop(), commands.Commands[3]);
            Assert.Equal(ServiceInstaller.Configure(pending.OldExe, true), commands.Commands[4]);
            if (!rollbackFails) Assert.Equal(ServiceInstaller.Start(), commands.Commands[5]);
        }
        Assert.True(File.Exists(pending.OldExe));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SilentPipeChecksRunningServiceImageBeforeMarkingBad(bool newVersionRunning)
    {
        using var temp = new TempDirectory();
        var root = Path.Combine(temp.Path, "app");
        var store = new UpdateStore(Path.Combine(temp.Path, "updates"));
        var host = new Host("silent");
        var pending = Pending(root, host.Now);
        store.WritePending(pending);
        // 管道不通但服务进程确实是新版：只回滚并下次再试，不写坏版本标记。
        host.RunningExe = newVersionRunning ? pending.NewExe : pending.OldExe;
        var commands = new Runner(pending, false);
        var applier = new UpdateApplier(store, commands, host, root, Path.GetFullPath("Windows/System32"));
        Assert.Equal(1, await applier.RunAsync());
        var last = store.ReadHistory().Last();
        Assert.Equal("rolled_back", last.Status);
        Assert.Equal(!newVersionRunning, store.IsBad("1.0.0"));
        Assert.False(store.HasPending);
        Assert.Equal(ServiceInstaller.Configure(pending.OldExe, true), commands.Commands[4]);
        Assert.Equal(pending.OldExe, host.RunExe);
        if (newVersionRunning)
        {
            Assert.Contains("下次再试", last.Reason);
            Assert.Empty(Directory.GetFiles(store.Root, "*.bad"));
        }
    }

    [Fact]
    public async Task LogWriteFailureCannotUndoSuccessfulServiceSwitch()
    {
        using var temp = new TempDirectory(); var host = new Host("ok");
        var root = Path.Combine(temp.Path, "app"); var store = new UpdateStore(Path.Combine(temp.Path, "updates"));
        var pending = Pending(root, host.Now); store.WritePending(pending);
        var runner = new Runner(pending, false);
        var applier = new UpdateApplier(store, runner, host, root, temp.Path, new FailingLog());
        Assert.Equal(0, await applier.RunAsync()); Assert.Equal(3, runner.Commands.Count);
        Assert.Equal("ok", store.ReadHistory().Last().Status); Assert.False(store.HasPending);
    }
    private sealed class FailingLog : ILog { public void Write(string message) => throw new IOException(); }

    [Fact]
    public async Task MissingOrCorruptPendingReturnsTwoWithoutCommands()
    {
        using var temp = new TempDirectory();
        var store = new UpdateStore(temp.Path); var host = new Host("ok");
        var runner = new Runner(Pending(Path.Combine(temp.Path, "app"), host.Now), false);
        var applier = new UpdateApplier(store, runner, host, Path.Combine(temp.Path, "app"), temp.Path);
        Assert.Equal(2, await applier.RunAsync());
        File.WriteAllText(store.PendingPath, "broken"); Assert.Equal(2, await applier.RunAsync());
        Assert.Empty(runner.Commands);
    }

    [Theory]
    [InlineData(false, 11, "rolled_back")]
    [InlineData(true, 11, "ok")]
    [InlineData(true, 9, null)]
    public void StartupRecoversOnlyStalePending(bool onNew, int minutes, string? expected)
    {
        using var temp = new TempDirectory(); var host = new Host("ok");
        var root = Path.Combine(temp.Path, "app"); var store = new UpdateStore(Path.Combine(temp.Path, "updates"));
        var pending = Pending(root, host.Now - TimeSpan.FromMinutes(minutes)); store.WritePending(pending);
        UpdateRecovery.Run(store, onNew ? pending.NewExe : pending.OldExe, host, root);
        Assert.Equal(expected is null, store.HasPending);
        if (expected is not null) Assert.Equal(expected, store.ReadHistory().Last().Status);
        Assert.Equal(expected == "rolled_back", store.IsBad("1.0.0"));
    }

    private static UpdatePending Pending(string root, DateTimeOffset at)
    {
        var old = UpdatePlanner.Executable(root, "0.1.0"); var next = UpdatePlanner.Executable(root, "1.0.0");
        foreach (var path in new[] { old, next }) { Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, "test"); }
        return new(old, "0.1.0", next, "1.0.0", at);
    }
    private sealed class Runner(UpdatePending pending, bool rollbackFails) : ICommandRunner
    {
        public List<string[]> Commands { get; } = [];
        public Task<CommandResult> RunAsync(ProcessStartInfo info, CancellationToken cancellationToken = default)
        {
            Assert.True(info.CreateNoWindow); Assert.False(info.UseShellExecute);
            Assert.True(Path.IsPathFullyQualified(info.FileName)); Assert.Equal("sc.exe", Path.GetFileName(info.FileName));
            var args = info.ArgumentList.ToArray(); Commands.Add(args);
            return Task.FromResult(new CommandResult(rollbackFails && args.Contains(ServiceInstaller.ServiceCommand(pending.OldExe)) ? 1 : 0, ""));
        }
    }
    private sealed class Host(string mode) : IUpdateHost
    {
        public DateTimeOffset Now { get; private set; } = DateTimeOffset.UtcNow;
        public string? RunExe;
        public bool DesiredConnection => mode == "network";
        public Task DelayAsync(TimeSpan delay, CancellationToken token) { Now += delay; return Task.CompletedTask; }
        public Task<bool> WaitServiceAsync(bool running, TimeSpan timeout, CancellationToken token) => Task.FromResult(true);
        public Task<ControlResponse?> ReadStatusAsync(CancellationToken token) => Task.FromResult<ControlResponse?>(mode == "silent" ? null :
            new(1, true, Snapshot: new ControlSnapshot(mode == "network" ? ConnectionState.Reconnecting : ConnectionState.Connected, "", "", true)
            { ServiceVersion = mode == "wrong_version" ? "0.1.0" : "1.0.0" }));
        public void SetRunValue(string exe) => RunExe = exe;
        // 默认 null：既有数据行仍按「服务进程查不到」处理，行为不变。
        public string? RunningExe { get; set; }
        public string? RunningServiceExecutable() => RunningExe;
    }
}
