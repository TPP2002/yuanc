using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using WinClient.Core.Client;
using WinClient.Core.Update;

namespace WinClient.Core.Ipc;

public sealed class ControlServer(IClientFacade facade, DesiredStateStore desired, IUpdateCoordinator? updates = null, string? serviceVersion = null)
{
    // One ordering across connections keeps persisted intent consistent with completed commands.
    private readonly SemaphoreSlim commands = new(1, 1);
    private ControlSnapshot Snapshot() => ((ControlSnapshot)facade.Snapshot) with
    { ServiceVersion = serviceVersion ?? ControlSnapshot.CurrentVersion, Update = updates?.Status ?? new() };

    public async Task ServeAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        using (stream)
        using (var closed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            var queue = Channel.CreateBounded<object>(64);
            var subscribed = false;
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
            try
            {
                var reader = new ControlLineReader(stream);
                while (await reader.ReadAsync(closed.Token).ConfigureAwait(false) is { } line)
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
                    else Enqueue(await ExecuteAsync(request, closed.Token).ConfigureAwait(false));
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

    private async Task<ControlResponse> ExecuteAsync(ControlRequest request, CancellationToken token)
    {
        if (request.Op == "check_update")
        {
            if (updates is not null) _ = updates.CheckNowAsync();
            return new(request.Id, true, Snapshot: Snapshot());
        }
        await commands.WaitAsync(token).ConfigureAwait(false);
        try
        {
            switch (request.Op)
            {
                case "status": break;
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
                case "read_audit":
                    var response = new ControlResponse(request.Id, true, Audit: facade.ReadAudit());
                    return ControlProtocol.Utf8.GetByteCount(ControlProtocol.Encode(response)) - 1 <= ControlProtocol.MaxLineBytes
                        ? response : new(request.Id, false, "审计记录过大，请联系管理员。");
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
