using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using WinClient.Core.Client;
using WinClient.Core.Update;

namespace WinClient.Core.Ipc;

public sealed class ControlServer(IClientFacade facade, DesiredStateStore desired, IUpdateCoordinator? updates = null, string? serviceVersion = null,
    TimeSpan? idleTimeout = null)
{
    public static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromSeconds(30);
    /// <summary>不可信调用者发会改变连接状态的指令时返回的错误文案。</summary>
    public const string UntrustedCallerError = "只有本产品的界面程序可以执行此操作";
    // 会改变连接状态的指令，以及 check_update（会触发对外网络检查）、read_audit（含本机其他程序的规则名与完整路径）、read_selfcheck（含产品核验到的真实出口地址），只允许程序位于安装目录之下的调用者执行；status 与 subscribe 对任何本机程序开放。
    private static readonly HashSet<string> TrustedOnlyOps = ["connect", "disconnect", "redeem", "import_pairing", "clear_pairing", "set_environment", "set_routing", "check_update", "read_audit", "read_selfcheck"];
    // One ordering across connections keeps persisted intent consistent with completed commands.
    private readonly SemaphoreSlim commands = new(1, 1);
    // 未订阅连接的空闲上限；零或负数表示不限。已订阅连接靠推送保活，不受此限。
    private readonly TimeSpan idleLimit = idleTimeout ?? DefaultIdleTimeout;
    private ControlSnapshot Snapshot() => ((ControlSnapshot)facade.Snapshot) with
    { ServiceVersion = serviceVersion ?? ControlSnapshot.CurrentVersion, Update = updates?.Status ?? new() };

    /// <param name="callerTrusted">调用者是否可信（由宿主按调用者程序路径判定）；默认 true 保持既有行为。
    /// 为 false 时会改变连接状态的指令一律拒绝，只读指令照常。</param>
    public async Task ServeAsync(Stream stream, CancellationToken cancellationToken = default, bool callerTrusted = true)
    {
        using (stream)
        using (var closed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        using (var idle = new CancellationTokenSource())
        using (idle.Token.Register(static state => ((CancellationTokenSource)state!).Cancel(), closed))
        {
            var queue = Channel.CreateBounded<object>(64);
            var subscribed = false;
            var limitIdle = idleLimit > TimeSpan.Zero;
            // 只用 CancelAfter 计时与重置，不开线程；计时到点即取消 closed，读循环退出后关流。
            void ArmIdle() { if (limitIdle && !subscribed) idle.CancelAfter(idleLimit); }
            // 指令执行期间连接并不空闲（可能在排队等前一条指令），暂停计时，回完响应再重新计时。
            void PauseIdle() { if (limitIdle) idle.CancelAfter(Timeout.InfiniteTimeSpan); }
            var sendGate = new object();
            var active = true;
            void Enqueue(object value)
            {
                lock (sendGate)
                {
                    if (!active) return;
                    if (!queue.Writer.TryWrite(value)) closed.Cancel();
                }
            }
            void Changed(ClientSnapshot snapshot) => Enqueue(new SnapshotEvent("snapshot", Snapshot()));
            void UpdateChanged(UpdateStatus status) => Enqueue(new SnapshotEvent("snapshot", Snapshot()));
            async Task WriteLoop()
            {
                try
                {
                    await foreach (var message in queue.Reader.ReadAllAsync(closed.Token).ConfigureAwait(false))
                        await ControlProtocol.WriteAsync(stream, message, closed.Token).ConfigureAwait(false);
                }
                finally { closed.Cancel(); }
            }
            var writing = WriteLoop();
            ArmIdle();
            try
            {
                var reader = new ControlLineReader(stream);
                while (await reader.ReadAsync(closed.Token).ConfigureAwait(false) is { } line)
                {
                    PauseIdle();
                    try
                    {
                        ControlRequest request;
                        try { request = ControlProtocol.DecodeRequest(line); }
                        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
                        { Enqueue(new ControlResponse(null, false, "指令格式错误")); continue; }
                        if (request.Op == "subscribe")
                        {
                            if (!subscribed) { facade.Changed += Changed; if (updates is not null) updates.Changed += UpdateChanged; subscribed = true; }
                            Enqueue(new ControlResponse(request.Id, true, Snapshot: Snapshot()));
                        }
                        else Enqueue(await ExecuteAsync(request, callerTrusted, closed.Token).ConfigureAwait(false));
                    }
                    finally { ArmIdle(); }
                }
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or DecoderFallbackException or ObjectDisposedException) { }
            finally
            {
                lock (sendGate)
                {
                    active = false;
                    if (subscribed) facade.Changed -= Changed;
                    if (subscribed && updates is not null) updates.Changed -= UpdateChanged;
                    queue.Writer.TryComplete();
                    closed.Cancel();
                }
                try { await writing.ConfigureAwait(false); }
                catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or ObjectDisposedException) { }
            }
        }
    }

    private async Task<ControlResponse> ExecuteAsync(ControlRequest request, bool callerTrusted, CancellationToken token)
    {
        // 不可信调用者：不进指令信号量、不调门面、不写期望状态，直接拒绝。
        if (!callerTrusted && TrustedOnlyOps.Contains(request.Op)) return new(request.Id, false, UntrustedCallerError);
        if (request.Op == "check_update")
        {
            if (updates is not null) _ = updates.CheckNowAsync();
            return new(request.Id, true, Snapshot: Snapshot());
        }
        // status 只读快照，不进指令信号量：长指令执行期间探活与界面刷新也能立即拿到状态。
        if (request.Op == "status") return new(request.Id, true, Snapshot: Snapshot());
        await commands.WaitAsync(token).ConfigureAwait(false);
        try
        {
            switch (request.Op)
            {
                case "connect":
                    await facade.ConnectAsync().ConfigureAwait(false);
                    desired.Write(true);
                    break;
                case "disconnect":
                    await facade.DisconnectAsync().ConfigureAwait(false);
                    desired.Write(false);
                    break;
                case "redeem": await facade.RedeemAsync(request.Code ?? "").ConfigureAwait(false); break;
                case "import_pairing": await facade.ImportPairingAsync(request.PairingJson ?? "").ConfigureAwait(false); break;
                case "clear_pairing": await facade.ClearPairingAsync().ConfigureAwait(false); break;
                case "set_environment":
                    if (request.Enabled is null) return new(request.Id, false, "指令缺少 enabled");
                    await facade.SetEnvironmentEnabledAsync(request.Enabled.Value).ConfigureAwait(false);
                    break;
                case "set_routing":
                    if (request.Mode is null) return new(request.Id, false, "指令缺少 mode");
                    await facade.SetRoutingAsync(request.Mode, request.Apps ?? []).ConfigureAwait(false);
                    break;
                case "read_audit":
                    var response = new ControlResponse(request.Id, true, Audit: facade.ReadAudit());
                    return ControlProtocol.Utf8.GetByteCount(ControlProtocol.Encode(response)) - 1 <= ControlProtocol.MaxLineBytes
                        ? response : new(request.Id, false, "审计记录过大，请联系管理员。");
                case "read_selfcheck":
                    var selfCheckResponse = new ControlResponse(request.Id, true, SelfCheck: facade.ReadSelfCheck());
                    return ControlProtocol.Utf8.GetByteCount(ControlProtocol.Encode(selfCheckResponse)) - 1 <= ControlProtocol.MaxLineBytes
                        ? selfCheckResponse : new(request.Id, false, "自检报告过大，请联系管理员。");
                default: return new(request.Id, false, "不支持的指令");
            }
            return new(request.Id, true, Snapshot: Snapshot());
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or JsonException or CryptographicException)
        {
            // Never send exception text: it can contain caller-supplied pairing data or secrets.
            return new(request.Id, false, "操作未完成，请检查输入内容；更换配对文件前请先断开，或联系管理员。");
        }
        finally { commands.Release(); }
    }
}
