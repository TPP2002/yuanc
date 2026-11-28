using System.IO;
using WinClient.Core.Firewall;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.Logging;
using WinClient.Core.State;
using WinClient.Core.Update;

namespace WinClient.App.Hosting;

public interface IUpdateHost
{
    DateTimeOffset Now { get; }
    bool DesiredConnection { get; }
    Task DelayAsync(TimeSpan delay, CancellationToken token);
    Task<bool> WaitServiceAsync(bool running, TimeSpan timeout, CancellationToken token);
    Task<ControlResponse?> ReadStatusAsync(CancellationToken token);
    void SetRunValue(string executable);
    // 把开始菜单图标、桌面图标、卸载入口指到这份程序。
    void SetEntryPoints(string executable, string version);
    /// <summary>服务正在运行且能查到服务进程的程序完整路径时返回规范化路径，否则 null。</summary>
    string? RunningServiceExecutable();
}

/// <summary>Transaction logic is tested with fake commands and pipe responses; Windows adapters live separately.</summary>
public sealed class UpdateApplier(UpdateStore store, ICommandRunner runner, IUpdateHost host,
    string appRoot, string systemDirectory, ILog? logger = null)
{
    private readonly ILog log = new UpdateLog(logger ?? NullLog.Instance);
    public static void ValidatePaths(UpdatePending pending, string appRoot)
    {
        foreach (var pair in new[] { (pending.OldExe, pending.OldVersion), (pending.NewExe, pending.NewVersion) })
        {
            if (!string.Equals(Path.GetFullPath(pair.Item1), UpdatePlanner.Executable(appRoot, pair.Item2), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("更新恢复目录不正确。");
            for (var directory = new DirectoryInfo(Path.GetDirectoryName(pair.Item1)!); directory is not null; directory = directory.Parent)
                if (directory.Exists && directory.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("更新目录不能是链接。");
            if (File.Exists(pair.Item1) && File.GetAttributes(pair.Item1).HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("更新程序不能是链接。");
        }
    }
    private async Task CommandAsync(string[] arguments, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var result = await runner.RunAsync(ServiceInstaller.CreateStartInfo(systemDirectory, arguments), timeout.Token).ConfigureAwait(false);
        if (result.ExitCode != 0) throw new InvalidOperationException("后台服务操作未完成。");
    }
    private async Task StopAsync(CancellationToken token)
    {
        // Stop may report already stopped; status is still required before changing binPath.
        try { await CommandAsync(UpdatePlanner.Stop(), token).ConfigureAwait(false); }
        catch (InvalidOperationException) { }
        if (!await host.WaitServiceAsync(false, TimeSpan.FromSeconds(30), token).ConfigureAwait(false)) throw new InvalidOperationException("后台服务未能停止。");
    }
    public async Task<int> RunAsync(CancellationToken token = default)
    {
        var pending = store.ReadPending();
        if (pending is null) return 2;
        try { ValidatePaths(pending, appRoot); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException) { log.Write("更新恢复记录无效，请联系维护人员。"); return 2; }
        var badProcess = false;
        try
        {
            await StopAsync(token).ConfigureAwait(false);
            await CommandAsync(UpdatePlanner.Configure(pending.NewExe), token).ConfigureAwait(false);
            await CommandAsync(UpdatePlanner.Start(), token).ConfigureAwait(false);
            if (!await host.WaitServiceAsync(true, TimeSpan.FromSeconds(30), token).ConfigureAwait(false)) throw new InvalidOperationException();
            var deadline = host.Now + TimeSpan.FromSeconds(60);
            ControlSnapshot? healthy = null;
            while (host.Now < deadline)
            {
                var probeStarted = host.Now;
                using var probe = CancellationTokenSource.CreateLinkedTokenSource(token);
                probe.CancelAfter(TimeSpan.FromSeconds(Math.Min(2, (deadline - host.Now).TotalSeconds)));
                ControlResponse? response;
                try { response = await host.ReadStatusAsync(probe.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { response = null; }
                if (response is { Ok: true, Snapshot: { } snapshot } && snapshot.ServiceVersion == pending.NewVersion)
                { healthy = snapshot; break; }
                var pause = Math.Min((deadline - host.Now).TotalSeconds, (probeStarted + TimeSpan.FromSeconds(2) - host.Now).TotalSeconds);
                if (pause > 0) await host.DelayAsync(TimeSpan.FromSeconds(pause), token).ConfigureAwait(false);
            }
            if (healthy is null)
            {
                // 管道 60 秒不通不一定是新版坏了（管道可能被别的程序占满）：服务进程确实是新版就只回滚、下次再试，不标坏。
                if (SameExecutable(host.RunningServiceExecutable(), pending.NewExe))
                {
                    log.Write("新版后台已在运行但本机管道暂不可用，本次不标记坏版本，下次再试。");
                    throw new InvalidOperationException();
                }
                badProcess = true; throw new InvalidOperationException();
            }
            if (host.DesiredConnection && healthy.State != ConnectionState.Connected)
            {
                deadline = host.Now + TimeSpan.FromSeconds(120);
                while (host.Now < deadline && healthy.State != ConnectionState.Connected)
                {
                    await host.DelayAsync(TimeSpan.FromSeconds(Math.Min(2, (deadline - host.Now).TotalSeconds)), token).ConfigureAwait(false);
                    if (host.Now >= deadline) break;
                    using var probe = CancellationTokenSource.CreateLinkedTokenSource(token);
                    probe.CancelAfter(TimeSpan.FromSeconds(Math.Min(2, (deadline - host.Now).TotalSeconds)));
                    ControlResponse? response;
                    try { response = await host.ReadStatusAsync(probe.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested) { response = null; }
                    if (response is { Ok: true, Snapshot: { } snapshot })
                    {
                        if (snapshot.ServiceVersion != pending.NewVersion) { badProcess = true; throw new InvalidOperationException(); }
                        healthy = snapshot;
                    }
                }
                if (healthy.State != ConnectionState.Connected) throw new InvalidOperationException();
            }
            Complete(store, pending, host, appRoot, log);
            return 0;
        }
        catch (Exception)
        {
            if (badProcess)
            {
                try { store.MarkBad(pending.NewVersion); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("坏版本标记未能保存，仍将尝试恢复旧版。"); }
            }
            try
            {
                // A cancelled forward transaction must still get its own bounded rollback attempts.
                await StopAsync(CancellationToken.None).ConfigureAwait(false);
                await CommandAsync(UpdatePlanner.Configure(pending.OldExe), CancellationToken.None).ConfigureAwait(false);
                await CommandAsync(UpdatePlanner.Start(), CancellationToken.None).ConfigureAwait(false);
                if (!await host.WaitServiceAsync(true, TimeSpan.FromSeconds(30), CancellationToken.None).ConfigureAwait(false)) throw new InvalidOperationException();
                host.SetRunValue(pending.OldExe);
                RefreshEntryPoints(host, pending.OldExe, pending.OldVersion, log);
                if (badProcess) store.MarkBad(pending.NewVersion);
                store.AppendHistory(pending.NewVersion, "rolled_back", host.Now, badProcess ? "新版后台未能响应，已恢复旧版。" : "更新未完成，已恢复旧版，下次再试。");
                store.DeletePending();
                log.Write("更新未完成，已恢复旧版。");
            }
            catch (Exception)
            {
                try { store.AppendHistory(pending.NewVersion, "needs_manual", host.Now, "自动恢复未完成，请联系维护人员。"); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("恢复记录未能保存。"); }
                log.Write("自动恢复未完成，恢复记录已保留，请联系维护人员。");
            }
            return 1;
        }
    }
    private static bool SameExecutable(string? running, string expected)
    {
        if (string.IsNullOrEmpty(running)) return false;
        try { return string.Equals(Path.GetFullPath(running), Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException) { return false; }
    }
    internal static void Complete(UpdateStore store, UpdatePending pending, IUpdateHost host, string appRoot, ILog log)
    {
        host.SetRunValue(pending.NewExe);
        RefreshEntryPoints(host, pending.NewExe, pending.NewVersion, log);
        store.AppendHistory(pending.NewVersion, "ok", host.Now);
        store.DeletePending();
        try
        {
            var plan = UpdatePlanner.Plan(appRoot, Path.GetDirectoryName(pending.OldExe)!, pending.NewVersion,
                Directory.GetDirectories(appRoot), store.ReadPending());
            foreach (var directory in plan.DeleteDirectories)
            {
                try
                {
                    // Never traverse links; a running older UI can also legitimately keep a directory busy.
                    if (HasLinks(new DirectoryInfo(directory))) continue;
                    Directory.Delete(directory, recursive: true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("旧版目录暂时无法清理，已保留。"); }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("旧版目录暂时无法清理，已保留。"); }
        log.Write("后台更新成功。");
    }
    private static bool HasLinks(DirectoryInfo directory)
    {
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint)) return true;
        foreach (var item in directory.EnumerateFileSystemInfos())
            if (item.Attributes.HasFlag(FileAttributes.ReparsePoint) || item is DirectoryInfo child && HasLinks(child)) return true;
        return false;
    }
    // 图标和卸载入口只是入口，更新不成不能连累已经换好的后台服务。
    private static void RefreshEntryPoints(IUpdateHost host, string executable, string version, ILog log)
    {
        try { host.SetEntryPoints(executable, version); }
        catch (Exception) { log.Write("开始菜单图标、桌面图标或卸载入口未能更新。"); }
    }
}
