using System.Net;
using System.Text;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Logging;
using Xunit;

namespace WinClient.Tests;

public sealed class AuthTests
{
    [Theory]
    [InlineData(200, AuthResult.Ok)] [InlineData(204, AuthResult.Ok)]
    [InlineData(401, AuthResult.InvalidToken)] [InlineData(403, AuthResult.Disabled)]
    [InlineData(410, AuthResult.Expired)] [InlineData(409, AuthResult.DeviceLimit)]
    [InlineData(423, AuthResult.Revoked)] [InlineData(429, AuthResult.RateLimited)]
    [InlineData(404, AuthResult.InviteNotFound)] [InlineData(422, AuthResult.InvalidParameters)]
    [InlineData(500, AuthResult.UnexpectedResponse)]
    public async Task MapsHttpResponsesWithoutLoggingBody(int code, AuthResult expected)
    {
        var log = new MemoryLog();
        using var client = new HttpClient(new Handler(_ => new((HttpStatusCode)code)
        { Content = new StringContent("secret-body") })) { BaseAddress = new("https://unit.invalid") };
        Assert.Equal(expected, await new AuthApiClient(client, log).LogoutAsync("private-refresh"));
        Assert.DoesNotContain("private-refresh", string.Join("", log.Lines));
        Assert.DoesNotContain("secret-body", string.Join("", log.Lines));
    }

    [Fact]
    public async Task ThreeEndpointsSerializeAndDeserializeContract()
    {
        var requests = new List<(string Path, string Body)>();
        using var client = new HttpClient(new Handler(request =>
        {
            requests.Add((request.RequestUri!.AbsolutePath, request.Content!.ReadAsStringAsync().GetAwaiter().GetResult()));
            var json = request.RequestUri.AbsolutePath switch
            {
                "/client/redeem" => """{"account_id":"account","expires_at":"2030-01-01T00:00:00Z","refresh_token":"new-refresh","device_id":"device"}""",
                "/client/session" => JsonSerializer.Serialize(TestData.Session(), new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower }),
                _ => ""
            };
            return new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        })) { BaseAddress = new("https://unit.invalid") };
        var api = new AuthApiClient(client);
        var redeemed = await api.RedeemAsync(new() { Code = "invite", Device = TestData.Device, RefreshToken = "old-refresh" });
        Assert.Equal("new-refresh", redeemed.Value!.RefreshToken);
        var session = await api.SessionAsync(redeemed.Value.RefreshToken);
        Assert.Equal(AuthResult.Ok, session.Result);
        Assert.Equal("192.0.2.5", session.Value!.Node.Host);
        Assert.Equal(AuthResult.Ok, await api.LogoutAsync("new-refresh"));
        Assert.Equal(new[] { "/client/redeem", "/client/session", "/client/logout" }, requests.Select(r => r.Path));
        using var body = JsonDocument.Parse(requests[0].Body);
        Assert.Equal("invite", body.RootElement.GetProperty("code").GetString());
        Assert.Equal("windows", body.RootElement.GetProperty("device").GetProperty("platform").GetString());
        Assert.Equal("old-refresh", body.RootElement.GetProperty("refresh_token").GetString());
        Assert.Contains("refresh_token", requests[1].Body);
    }

    [Fact]
    public async Task NetworkMalformedJsonAndCallerCancellationAreDistinct()
    {
        using var network = new HttpClient(new Handler(_ => throw new HttpRequestException())) { BaseAddress = new("https://unit.invalid") };
        Assert.Equal(AuthResult.Network, (await new AuthApiClient(network).SessionAsync("token")).Result);
        using var malformed = new HttpClient(new Handler(_ => new(HttpStatusCode.OK) { Content = new StringContent("{") })) { BaseAddress = new("https://unit.invalid") };
        Assert.Equal(AuthResult.UnexpectedResponse, (await new AuthApiClient(malformed).SessionAsync("token")).Result);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AuthApiClient(network).SessionAsync("token", cancelled.Token));
    }

    [Fact]
    public void LogsRedactOpaqueAndLabelledTokens()
    {
        var sink = new MemoryLog(); var log = new RedactingLog(sink);
        log.RegisterSecret("opaque-secret");
        log.Write("opaque-secret refresh_token=other-secret Authorization: Bearer bearer-secret");
        var output = Assert.Single(sink.Lines);
        Assert.DoesNotContain("opaque-secret", output);
        Assert.DoesNotContain("other-secret", output);
        Assert.DoesNotContain("bearer-secret", output);
    }

    internal sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(send(request)); }
    }
    internal sealed class MemoryLog : ILog
    {
        public List<string> Lines { get; } = [];
        public void Write(string message) => Lines.Add(message);
    }
}
