using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WinClient.Core.Diagnostics;

/// <summary>连接内核状态口的回环地址与随机口令；口令不进日志与诊断。</summary>
public sealed record KernelStatusEndpoint(int Port, string Secret)
{
    /// <summary>取一个空闲回环端口并生成 32 位十六进制口令。</summary>
    public static KernelStatusEndpoint Create()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return new(port, Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
    }

    /// <summary>只打印地址，不含口令。</summary>
    public override string ToString() => $"127.0.0.1:{Port}";
}

public sealed record ChannelStateResult(string? Json, string? Error);

/// <summary>只读连接内核的状态口，取当前选中的通道、主备最近一次测速与现场复测结果。</summary>
public static class KernelChannelProbe
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(6);
    public const int DelayTimeoutMs = 3000;
    public const string TestUrl = "https://www.gstatic.com/generate_204";
    public const string NotRunning = "通道状态没有读到：连接内核没有在运行。";
    public const string TimedOut = "通道状态没有读到：超过时限没有返回。";
    public const string Failed = "通道状态没有读到：内核的状态口没有正常应答。";

    public static async Task<ChannelStateResult> RunAsync(KernelStatusEndpoint? endpoint, HttpMessageHandler? handler = null, TimeSpan? timeout = null, CancellationToken token = default)
    {
        if (endpoint is null) return new(null, NotRunning);
        token.ThrowIfCancellationRequested();
        using var source = CancellationTokenSource.CreateLinkedTokenSource(token);
        source.CancelAfter(timeout ?? DefaultTimeout);
        var ownsHandler = handler is null;
        var effective = handler ?? new SocketsHttpHandler { UseProxy = false };
        using var client = new HttpClient(effective, disposeHandler: ownsHandler);
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", endpoint.Secret);
        var origin = $"http://127.0.0.1:{endpoint.Port}";
        try
        {
            using var first = await client.GetAsync(origin + "/proxies", source.Token).ConfigureAwait(false);
            if (!first.IsSuccessStatusCode) return new(null, Failed);
            var body = await first.Content.ReadAsStringAsync(source.Token).ConfigureAwait(false);
            JsonNode? parsed;
            try { parsed = JsonNode.Parse(body); }
            catch (JsonException) { return new(null, Failed); }
            if (parsed is not JsonObject root || root["proxies"] is not JsonObject proxies || proxies["proxy"] is not JsonObject proxy)
                return new(null, Failed);
            var selected = proxy["now"] is JsonValue nowValue && nowValue.TryGetValue<string>(out var nowText) ? nowText : null;
            var (mainDelay, mainTime) = LastHistory(proxies, "main");
            var (backupDelay, backupTime) = LastHistory(proxies, "backup");
            // 两条测速先同时发出，再逐个等结果。
            var mainTest = DelayTestAsync(client, origin, "main", source.Token);
            var backupTest = DelayTestAsync(client, origin, "backup", source.Token);
            var main = await mainTest.ConfigureAwait(false);
            var backup = await backupTest.ConfigureAwait(false);
            var json = new JsonObject
            {
                ["selected"] = selected,
                ["main"] = ChannelNode(mainDelay, mainTime, main),
                ["backup"] = ChannelNode(backupDelay, backupTime, backup)
            };
            return new(json.ToJsonString(), null);
        }
        catch (OperationCanceledException)
        {
            // 只有本方法的计时器到点才算超时；外部令牌取消照旧透出。
            if (token.IsCancellationRequested) throw;
            return new(null, TimedOut);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException)
        {
            return new(null, Failed);
        }
    }

    private static (int? Delay, string? Time) LastHistory(JsonObject proxies, string name)
    {
        if (proxies[name] is not JsonObject outbound) return (null, null);
        if (outbound["history"] is not JsonArray history || history.Count == 0) return (null, null);
        if (history[^1] is not JsonObject last) return (null, null);
        int? delay = last["delay"] is JsonValue delayValue && delayValue.TryGetValue<int>(out var delayNumber) ? delayNumber : null;
        string? time = last["time"] is JsonValue timeValue && timeValue.TryGetValue<string>(out var timeText) ? timeText : null;
        return (delay, time);
    }

    private static async Task<DelayTest> DelayTestAsync(HttpClient client, string origin, string name, CancellationToken token)
    {
        try
        {
            using var response = await client.GetAsync(
                $"{origin}/proxies/{name}/delay?url={Uri.EscapeDataString(TestUrl)}&timeout={DelayTimeoutMs}",
                token).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            if (status != 200) return new(false, null, status);
            var body = await response.Content.ReadAsStringAsync(token).ConfigureAwait(false);
            try
            {
                if (JsonNode.Parse(body) is JsonObject obj && obj["delay"] is JsonValue delay &&
                    delay.TryGetValue<int>(out var delayNumber))
                    return new(true, delayNumber, 200);
            }
            catch (JsonException) { }
            return new(false, null, 200);
        }
        catch (HttpRequestException)
        {
            return new(false, null, 0);
        }
    }

    private static JsonObject ChannelNode(int? lastDelay, string? lastTestAt, DelayTest test) => new()
    {
        ["last_delay_ms"] = lastDelay is null ? null : JsonValue.Create(lastDelay.Value),
        ["last_test_at"] = lastTestAt,
        ["test_ok"] = test.Ok,
        ["test_delay_ms"] = test.Delay is null ? null : JsonValue.Create(test.Delay.Value),
        ["test_status"] = test.Status
    };

    private readonly record struct DelayTest(bool Ok, int? Delay, int Status);
}
