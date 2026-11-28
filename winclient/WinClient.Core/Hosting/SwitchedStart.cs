using WinClient.Core.Ipc;

namespace WinClient.Core.Hosting;

/// <summary>覆盖安装换程序之后，判断新后台是不是真的起来了，以及没起来时该报哪一句。</summary>
public static class SwitchedStart
{
    public const string RolledBackMessage = "新版本的后台服务未能启动，已改回原来的版本。";
    public const string NoPreviousMessage = "新版本的后台服务未能启动，原来的版本已经不在，没有改回。请重新安装，或联系管理员。";
    public const string RollbackNotRunningMessage = "新版本的后台服务未能启动，已改回原来的版本，但原来的后台服务也没能启动。请重启电脑，或联系管理员。";
    public static readonly TimeSpan HealthBudget = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(2);

    /// <summary>在 HealthBudget 内每隔 ProbeInterval 读一次后台状态；读到应答成功且版本等于 expectedVersion 才返回 true。</summary>
    public static async Task<bool> WaitHealthyAsync(Func<CancellationToken, Task<ControlResponse?>> readStatus,
        string expectedVersion, Func<DateTimeOffset> now, Func<TimeSpan, CancellationToken, Task> delay,
        CancellationToken token = default)
    {
        var deadline = now() + HealthBudget;
        while (now() < deadline)
        {
            token.ThrowIfCancellationRequested();
            var started = now();
            using var probe = CancellationTokenSource.CreateLinkedTokenSource(token);
            probe.CancelAfter(Shorter(ProbeInterval, deadline - started));
            ControlResponse? response;
            try { response = await readStatus(probe.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { response = null; }
            if (response is { Ok: true, Snapshot: { } snapshot } && snapshot.ServiceVersion == expectedVersion) return true;
            var pause = Shorter(deadline - now(), started + ProbeInterval - now());
            if (pause > TimeSpan.Zero) await delay(pause, token).ConfigureAwait(false);
        }
        return false;
    }

    /// <summary>previousAvailable：旧程序文件还在、做了改回；previousRunning：改回后旧后台起来了。</summary>
    public static string FailureMessage(bool previousAvailable, bool previousRunning) =>
        !previousAvailable ? NoPreviousMessage : previousRunning ? RolledBackMessage : RollbackNotRunningMessage;

    private static TimeSpan Shorter(TimeSpan left, TimeSpan right) => left < right ? left : right;
}
