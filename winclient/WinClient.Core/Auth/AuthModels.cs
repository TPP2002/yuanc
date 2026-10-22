using System.Net;
using System.Text.Json.Serialization;

namespace WinClient.Core.Auth;

public enum AuthResult
{
    Ok, InvalidToken, Disabled, Expired, DeviceLimit, Revoked,
    RateLimited, InviteNotFound, Network, InvalidParameters, UnexpectedResponse
}

public sealed class AuthResponse<T>(AuthResult result, T? value = default, HttpStatusCode? statusCode = null)
{
    public AuthResult Result { get; } = result;
    public T? Value { get; } = value;
    public HttpStatusCode? StatusCode { get; } = statusCode;
}

public sealed class DeviceInfo
{
    public required string Platform { get; init; }
    public required string Name { get; init; }
    public required string Fingerprint { get; init; }
}

public sealed class RedeemRequest
{
    public required string Code { get; init; }
    public required DeviceInfo Device { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; init; }
}

public sealed class RedeemResponse
{
    public required string AccountId { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required string RefreshToken { get; init; }
    public required string DeviceId { get; init; }
}

public sealed class SessionResponse
{
    public required string SessionToken { get; init; }
    public required DateTimeOffset SessionExpiresAt { get; init; }
    public required DateTimeOffset AccountExpiresAt { get; init; }
    public required NodeInfo Node { get; init; }
}

public sealed class NodeInfo
{
    [JsonPropertyName("time_zone")]
    public string TimeZone { get; init; } = "";
    [JsonPropertyName("country")]
    public string Country { get; init; } = "";
    public required string Host { get; init; }
    public required int RealityPort { get; init; }
    public required int Hy2Port { get; init; }
    public required string Sni { get; init; }
    public required string RealityPublicKey { get; init; }
    public required string ShortId { get; init; }
    public required string Uuid { get; init; }
    public required string Hy2Password { get; init; }
    public string Hy2ServerName { get; init; } = "exitnode";
    public string[] Hy2Certificate { get; init; } = [];
    // Node-level salamander obfuscation password; empty means the node has not enabled obfuscation.
    public string Hy2ObfsPassword { get; init; } = "";
}
