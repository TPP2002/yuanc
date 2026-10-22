using System.Net;

namespace WinClient.Core.Client;

public interface IExitProbe
{
    Task<IPAddress?> ProbeAsync(CancellationToken token);
}

/// <summary>由后台服务经隧道获取出口；不附带设备信息，不记录响应或地址。</summary>
public sealed class HttpExitProbe : IExitProbe, IDisposable
{
    private readonly HttpClient http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        UseCookies = false
    }) { Timeout = TimeSpan.FromSeconds(5) };

    public async Task<IPAddress?> ProbeAsync(CancellationToken token)
    {
        try
        {
            using var response = await http.GetAsync("https://1.1.1.1/cdn-cgi/trace", token).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK) return null;
            using var reader = new StringReader(await response.Content.ReadAsStringAsync(token).ConfigureAwait(false));
            while (reader.ReadLine() is { } line)
                if (line.StartsWith("ip=", StringComparison.Ordinal))
                    return IPAddress.TryParse(line[3..], out var address) ? address : null;
            return null;
        }
        catch (Exception) { return null; } // 网络、超时、取消及解析异常都只表示无法核验。
    }

    public void Dispose() => http.Dispose();
}
