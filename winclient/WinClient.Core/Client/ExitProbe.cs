using System.Net;
using System.Text.RegularExpressions;

namespace WinClient.Core.Client;

public sealed record ExitProbeResult(IPAddress Address, string? Country);

public interface IExitProbe
{
    Task<IPAddress?> ProbeAsync(CancellationToken token);
    async Task<ExitProbeResult?> ProbeDetailedAsync(CancellationToken token)
        => await ProbeAsync(token).ConfigureAwait(false) is { } address ? new(address, null) : null;
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
        => (await ProbeDetailedAsync(token).ConfigureAwait(false))?.Address;

    public async Task<ExitProbeResult?> ProbeDetailedAsync(CancellationToken token)
    {
        try
        {
            using var response = await http.GetAsync("https://1.1.1.1/cdn-cgi/trace", token).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK) return null;
            return Parse(await response.Content.ReadAsStringAsync(token).ConfigureAwait(false));
        }
        catch (Exception) { return null; } // 网络、超时、取消及解析异常都只表示无法核验。
    }

    internal static ExitProbeResult? Parse(string body)
    {
        IPAddress? address = null;
        string? country = null;
        using var reader = new StringReader(body);
        while (reader.ReadLine() is { } line)
        {
            if (line.StartsWith("ip=", StringComparison.Ordinal)) IPAddress.TryParse(line[3..], out address);
            else if (line.StartsWith("loc=", StringComparison.Ordinal))
                country = Regex.IsMatch(line[4..], "^[A-Z]{2}$") ? line[4..] : null;
        }
        return address is null ? null : new(address, country);
    }

    public void Dispose() => http.Dispose();
}
