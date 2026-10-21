using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace WinClient.Core.Update;

public sealed class HttpUpdateSource : IUpdateSource, IDisposable
{
    public const string BaseAddress = "http://198.18.255.1/winclient/";
    private readonly HttpClient http;
    public HttpUpdateSource() : this(new SocketsHttpHandler
    { UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(15) }) { }
    public HttpUpdateSource(HttpMessageHandler handler) => http = new(handler) { Timeout = Timeout.InfiniteTimeSpan };
    private static Uri Address(string name)
    {
        if (name != "latest.json" && !Regex.IsMatch(name, @"\AYuanC-Client-" + UpdateVersion.Pattern + @"(?:\.exe|\.manifest\.json(?:\.sig)?)\z"))
            throw new InvalidDataException("更新文件名不正确。");
        return new Uri(BaseAddress + name);
    }
    public async Task<UpdateIndex?> LatestAsync(CancellationToken token)
    {
        try { return UpdateIndex.Parse(await ReadAsync("latest.json", 65536, token).ConfigureAwait(false)); }
        catch (FileNotFoundException) { return null; }
    }
    public async Task<byte[]> ReadAsync(string name, int maximumBytes, CancellationToken token)
    {
        var ceiling = name.EndsWith(".sig", StringComparison.Ordinal) ? 4096 : 65536;
        maximumBytes = Math.Min(maximumBytes, ceiling);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var response = await http.GetAsync(Address(name), HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (name == "latest.json" && response.StatusCode == HttpStatusCode.NotFound) throw new FileNotFoundException("尚未托管客户端包。");
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength > maximumBytes)
            throw new InvalidDataException("更新文件响应不正确。");
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[4096]; int count;
        while ((count = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) != 0)
        {
            if (output.Length + count > maximumBytes) throw new InvalidDataException("更新文件过大。");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }
    public async Task DownloadAsync(UpdateManifest manifest, string temporaryFile, CancellationToken token)
    {
        if (manifest.Size < 0 || manifest.Size > UpdateManifest.MaxPayloadBytes) throw new InvalidDataException("更新文件过大。");
        Directory.CreateDirectory(Path.GetDirectoryName(temporaryFile)!);
        var offset = File.Exists(temporaryFile) ? new FileInfo(temporaryFile).Length : 0;
        if (offset > manifest.Size) { File.Delete(temporaryFile); offset = 0; }
        if (offset == manifest.Size && File.Exists(temporaryFile)) return; // Coordinator still verifies every byte.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(20));
        using var request = new HttpRequestMessage(HttpMethod.Get, Address(manifest.File));
        if (offset > 0) request.Headers.Range = new RangeHeaderValue(offset, null);
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.PartialContent)
        {
            var range = response.Content.Headers.ContentRange;
            if (range is null || range.Unit != "bytes" || range.From != offset || range.To != manifest.Size - 1 || range.Length != manifest.Size)
                throw new InvalidDataException("续传响应不正确。");
        }
        else if (response.StatusCode == HttpStatusCode.OK) offset = 0;
        else throw new InvalidDataException("更新下载未成功。");
        if (response.Content.Headers.ContentLength is { } length && length != manifest.Size - offset)
            throw new InvalidDataException("更新下载大小不符。");
        await using var input = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        await using var output = new FileStream(temporaryFile, offset == 0 ? FileMode.Create : FileMode.Append, FileAccess.Write, FileShare.None);
        var buffer = new byte[65536]; int count; var total = offset;
        while ((count = await input.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) != 0)
        {
            total += count;
            if (total > manifest.Size || total > UpdateManifest.MaxPayloadBytes) throw new InvalidDataException("更新下载大小不符。");
            await output.WriteAsync(buffer.AsMemory(0, count), timeout.Token).ConfigureAwait(false);
        }
        output.Flush(true);
        if (total != manifest.Size) throw new InvalidDataException("更新下载不完整。");
    }
    public void Dispose() => http.Dispose();
}
