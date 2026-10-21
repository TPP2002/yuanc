using System.Collections.Concurrent;
using System.Text.Json;
using WinClient.Core.Client;

namespace WinClient.Core.Ipc;

public sealed class ControlClient : IDisposable
{
    private readonly Stream stream;
    private readonly CancellationTokenSource lifetime = new();
    private readonly SemaphoreSlim writes = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<ControlResponse>> pending = new();
    private readonly Task receiving;
    private long nextId;
    public event Action<ClientSnapshot>? Changed;
    public event Action<ControlSnapshot>? SnapshotChanged;
    public event Action? ConnectionClosed;
    public ControlClient(Stream stream) { this.stream = stream; receiving = ReceiveAsync(); }

    public async Task<ControlResponse> SendAsync(string op, string? code = null, string? pairingJson = null, CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token, cancellationToken);
        var id = Interlocked.Increment(ref nextId);
        var completion = new TaskCompletionSource<ControlResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        pending[id] = completion;
        try
        {
            await writes.WaitAsync(linked.Token).ConfigureAwait(false);
            try { await ControlProtocol.WriteAsync(stream, new ControlRequest(id, op, code, pairingJson), linked.Token).ConfigureAwait(false); }
            finally { writes.Release(); }
            return await completion.Task.WaitAsync(linked.Token).ConfigureAwait(false);
        }
        finally { pending.TryRemove(id, out _); }
    }

    private async Task ReceiveAsync()
    {
        try
        {
            var reader = new ControlLineReader(stream);
            while (await reader.ReadAsync(lifetime.Token).ConfigureAwait(false) is { } line)
            {
                using var json = JsonDocument.Parse(line);
                if (json.RootElement.TryGetProperty("event", out var kind) && kind.GetString() == "snapshot")
                {
                    var snapshot = ControlProtocol.DecodeEvent(line).Snapshot;
                    SnapshotChanged?.Invoke(snapshot);
                    Changed?.Invoke(snapshot);
                }
                else
                {
                    var response = ControlProtocol.DecodeResponse(line);
                    if (response.Id is { } id && pending.TryRemove(id, out var completion)) completion.TrySetResult(response);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or ObjectDisposedException or JsonException or System.Text.DecoderFallbackException) { }
        finally
        {
            lifetime.Cancel();
            foreach (var item in pending.Values) item.TrySetException(new IOException("后台服务连接已中断。"));
            ConnectionClosed?.Invoke();
        }
    }
    public void Dispose()
    {
        lifetime.Cancel();
        stream.Dispose();
        // The receive task owns its cancellation lifetime until its finally block completes.
    }
}
