using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WinClient.Core.Logging;

namespace WinClient.Core.Auth;

/// <summary>The caller owns the injected HttpClient (and can supply any HttpMessageHandler).</summary>
public sealed class AuthApiClient
{
    private readonly HttpClient http;
    private readonly RedactingLog log;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public AuthApiClient(HttpClient httpClient, ILog? logger = null)
    {
        http = httpClient;
        if (http.BaseAddress is null || http.BaseAddress.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("鉴权服务器必须配置为 HTTPS 地址。", nameof(httpClient));
        log = new RedactingLog(logger ?? NullLog.Instance);
    }

    public async Task<AuthResponse<RedeemResponse>> RedeemAsync(RedeemRequest request, CancellationToken cancellationToken = default)
    {
        log.RegisterSecret(request.Code);
        log.RegisterSecret(request.RefreshToken);
        var response = await SendAsync<RedeemResponse>("/client/redeem", request, cancellationToken);
        log.RegisterSecret(response.Value?.RefreshToken);
        return response;
    }

    public async Task<AuthResponse<SessionResponse>> SessionAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        log.RegisterSecret(refreshToken);
        var response = await SendAsync<SessionResponse>("/client/session", new { refresh_token = refreshToken }, cancellationToken);
        log.RegisterSecret(response.Value?.SessionToken);
        return response;
    }

    public async Task<AuthResult> LogoutAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        log.RegisterSecret(refreshToken);
        var response = await SendAsync<object>("/client/logout", new { refresh_token = refreshToken }, cancellationToken, readBody: false);
        return response.Result;
    }

    public static AuthResult MapStatus(HttpStatusCode status) => (int)status switch
    {
        >= 200 and <= 299 => AuthResult.Ok,
        401 => AuthResult.InvalidToken,
        403 => AuthResult.Disabled,
        410 => AuthResult.Expired,
        409 => AuthResult.DeviceLimit,
        423 => AuthResult.Revoked,
        429 => AuthResult.RateLimited,
        404 => AuthResult.InviteNotFound,
        422 => AuthResult.InvalidParameters,
        _ => AuthResult.UnexpectedResponse
    };

    private async Task<AuthResponse<T>> SendAsync<T>(string path, object body, CancellationToken ct, bool readBody = true)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = JsonContent.Create(body, options: Json)
            };
            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            var result = MapStatus(response.StatusCode);
            // Never log URLs, request bodies, response bodies, or exception messages.
            log.Write($"鉴权请求完成：{result}。");
            if (result != AuthResult.Ok || !readBody)
                return new(result, statusCode: response.StatusCode);
            var value = await response.Content.ReadFromJsonAsync<T>(Json, ct).ConfigureAwait(false);
            return value is null
                ? new(AuthResult.UnexpectedResponse, statusCode: response.StatusCode)
                : new(AuthResult.Ok, value, response.StatusCode);
        }
        catch (HttpRequestException)
        {
            log.Write("无法连接鉴权服务器。");
            return new(AuthResult.Network);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            log.Write("鉴权请求超时。");
            return new(AuthResult.Network);
        }
        catch (JsonException)
        {
            log.Write("鉴权服务器返回的数据格式不正确。");
            return new(AuthResult.UnexpectedResponse);
        }
    }
}
