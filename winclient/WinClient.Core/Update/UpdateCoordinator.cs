using System.Diagnostics;
using System.Security.Cryptography;
using WinClient.Core.Client;
using WinClient.Core.Logging;
using WinClient.Core.State;

namespace WinClient.Core.Update;

public sealed record UpdateStatus(string Stage = "idle", string? Version = null, string Message = "", DateTimeOffset? CheckedAt = null);
public interface IUpdateCoordinator
{
    UpdateStatus Status { get; }
    event Action<UpdateStatus>? Changed;
    Task<UpdateStatus> CheckNowAsync();
}

public sealed class UpdateCoordinator : IUpdateCoordinator, IDisposable
{
    private readonly IUpdateSource source;
    private readonly UpdateStore store;
    private readonly Func<ClientSnapshot> snapshot;
    private readonly Func<DateTimeOffset> clock;
    private readonly string currentVersion, appRoot, currentExe;
    private readonly ILog log;
    private readonly Action<string> launch;
    private readonly Func<ECDsa> publicKey;
    private readonly object gate = new();
    private readonly CancellationTokenSource lifetime = new();
    private Task<UpdateStatus>? active;
    private Task? schedule;
    private DateTimeOffset nextCheck;
    private bool handedOff;
    private UpdateStatus status = new();
    public UpdateStatus Status { get { lock (gate) return status; } }
    public event Action<UpdateStatus>? Changed;
    public UpdateCoordinator(IUpdateSource source, UpdateStore store, Func<ClientSnapshot> snapshot,
        Func<DateTimeOffset> clock, string currentVersion, ILog? log = null,
        string? appRoot = null, string? currentExe = null, Action<string>? launch = null, Func<ECDsa>? publicKey = null)
    {
        this.source = source; this.store = store; this.snapshot = snapshot; this.clock = clock;
        this.currentVersion = new UpdateVersion(currentVersion).Value;
        this.appRoot = Path.GetFullPath(appRoot ?? UpdatePlanner.DefaultAppRoot);
        this.currentExe = Path.GetFullPath(currentExe ?? Environment.ProcessPath ?? throw new InvalidOperationException("找不到当前后台程序。"));
        this.log = new UpdateLog(log ?? NullLog.Instance);
        this.launch = launch ?? Launch; this.publicKey = publicKey ?? TrustedPublisher.CreateKey;
        nextCheck = clock() + TimeSpan.FromMinutes(5);
    }
    private static void Launch(string oldExe)
    {
        var info = new ProcessStartInfo { FileName = Path.GetFullPath(oldExe), WorkingDirectory = Path.GetDirectoryName(oldExe)!, CreateNoWindow = true, UseShellExecute = false };
        info.ArgumentList.Add("--apply-update");
        using var process = System.Diagnostics.Process.Start(info) ?? throw new InvalidOperationException("无法启动更新助手。");
    }
    public void Start()
    {
        lock (gate) schedule ??= Task.Run(async () =>
        {
            try
            {
                while (!lifetime.IsCancellationRequested && !handedOff)
                {
                    var remaining = nextCheck - clock();
                    if (remaining > TimeSpan.Zero) await Task.Delay(remaining, lifetime.Token).ConfigureAwait(false);
                    await TickAsync().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        });
    }
    public Task<UpdateStatus> TickAsync() => clock() < nextCheck ? Task.FromResult(Status) : CheckNowAsync();
    public Task<UpdateStatus> CheckNowAsync()
    {
        lock (gate)
        {
            if (lifetime.IsCancellationRequested || handedOff || active is { IsCompleted: false }) return Task.FromResult(status);
            nextCheck = clock() + TimeSpan.FromHours(6);
            active = Task.Run(PerformAsync);
            return active;
        }
    }
    private void Set(string stage, string message, string? version = null)
    {
        UpdateStatus value;
        lock (gate) { value = status = new(stage, version, message, clock()); }
        Changed?.Invoke(value);
    }
    private async Task<UpdateStatus> PerformAsync()
    {
        string version = currentVersion;
        string? part = null, verified = null, targetTemporary = null;
        var wrotePending = false;
        try
        {
            Set("checking", "正在检查更新。");
            if (store.HasPending) { Skip("上次更新仍在处理，请稍后再试。"); return Status; }
            if (snapshot().State != ConnectionState.Connected) { Skip("连接后再检查更新。"); return Status; }
            var index = await source.LatestAsync(lifetime.Token).ConfigureAwait(false);
            if (index is null) { Skip("小主机尚未提供新版客户端。"); return Status; }
            version = new UpdateVersion(index.Version).Value;
            if (new UpdateVersion(version).CompareTo(new UpdateVersion(currentVersion)) <= 0)
            { Skip("当前后台已是最新版本。", "up_to_date"); return Status; }
            if (store.IsBad(version)) { Skip("此版本此前未能启动，已跳过。"); return Status; }
            var raw = await source.ReadAsync(index.Manifest, 65536, lifetime.Token).ConfigureAwait(false);
            var signed = await source.ReadAsync(index.Signature, 4096, lifetime.Token).ConfigureAwait(false);
            Set("verifying", "正在验证更新来源。", version);
            using var key = publicKey();
            var manifest = UpdateVerifier.VerifyManifest(raw, signed, key);
            index.Match(manifest);
            if (new UpdateVersion(manifest.MinServiceVersion).CompareTo(new UpdateVersion(currentVersion)) > 0)
                throw new InvalidDataException("当前后台版本不满足更新要求。");
            part = Path.Combine(store.Incoming, version + ".exe.part");
            verified = Path.Combine(store.Incoming, version + ".exe");
            Set("downloading", "正在下载更新，请保持连接。", version);
            await source.DownloadAsync(manifest, part, lifetime.Token).ConfigureAwait(false);
            Set("verifying", "正在检查下载文件。", version);
            using (var payload = File.OpenRead(part)) UpdateVerifier.VerifyPayload(payload, manifest);
            lifetime.Token.ThrowIfCancellationRequested();
            File.Move(part, verified, overwrite: true);
            if (!File.Exists(currentExe) || !string.Equals(currentExe, UpdatePlanner.Executable(appRoot, currentVersion), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("当前后台安装位置不正确。");
            var destination = UpdatePlanner.Executable(appRoot, version);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            targetTemporary = destination + ".tmp";
            using (var input = File.OpenRead(verified))
            using (var output = new FileStream(targetTemporary, FileMode.Create, FileAccess.Write, FileShare.None))
            { input.CopyTo(output); output.Flush(true); }
            File.Move(targetTemporary, destination, overwrite: true);
            using (var payload = File.OpenRead(destination)) UpdateVerifier.VerifyPayload(payload, manifest);
            lifetime.Token.ThrowIfCancellationRequested();
            store.WritePending(new(currentExe, currentVersion, destination, version, clock())); wrotePending = true;
            store.AppendHistory(version, "staged", clock());
            Set("staged", "新版已准备好，即将更新后台。", version);
            lifetime.Token.ThrowIfCancellationRequested();
            launch(currentExe);
            lock (gate) handedOff = true;
            Set("applying", "正在更新后台，连接可能短暂中断。", version);
        }
        catch (Exception)
        {
            if (!handedOff)
            {
                if (wrotePending)
                {
                    try { store.DeletePending(); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("更新恢复记录未能清理，请联系维护人员。"); }
                }
                Set("failed", lifetime.IsCancellationRequested ? "更新已取消，下次再试。" : "更新未完成，当前版本继续使用，下次再试。", version);
                try { store.AppendHistory(version, "failed", clock(), Status.Message); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("更新失败记录未能保存，请联系维护人员。"); }
                log.Write(Status.Message);
            }
        }
        finally
        {
            foreach (var path in new[] { part, targetTemporary, handedOff ? null : verified })
                if (path is not null)
                {
                    try { File.Delete(path); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Write("更新临时文件未能清理，请联系维护人员。"); }
                }
        }
        return Status;
        void Skip(string reason, string stage = "idle")
        { store.AppendHistory(version, "skipped", clock(), reason); Set(stage, reason, version); }
    }
    public void Cancel() => lifetime.Cancel();
    public async Task StopAsync()
    {
        Cancel();
        if (schedule is not null) await schedule.ConfigureAwait(false);
        if (active is not null) await active.ConfigureAwait(false);
    }
    public void Dispose() { Cancel(); }
}
