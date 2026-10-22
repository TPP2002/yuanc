using System.Text.Json;
using WinClient.Core.Auth;

namespace WinClient.Tests;

internal static class TestData
{
    public static DeviceInfo Device => new() { Platform = "windows", Name = "test", Fingerprint = "test-device" };
    public static JsonElement Config => JsonSerializer.SerializeToElement(new { inbounds = new[] { new { type = "tun" } } });
    public static SessionResponse Session(string host = "192.0.2.5") => new()
    {
        SessionToken = "test-session", SessionExpiresAt = DateTimeOffset.UtcNow.AddHours(6),
        AccountExpiresAt = DateTimeOffset.UtcNow.AddDays(1), SingboxConfig = Config,
        Node = new() { Host = host, RealityPort = 443, Hy2Port = 8443, Sni = "unit.invalid", RealityPublicKey = "test-key",
            ShortId = "test-short", Uuid = "test-uuid", Hy2Password = "test-password" }
    };

    /// <summary>构造节点信息，各字段可单独改写，供续期与会话比较测试使用。</summary>
    public static NodeInfo Node(string host = "192.0.2.5", int realityPort = 443, int hy2Port = 8443,
        string sni = "unit.invalid", string realityPublicKey = "test-key", string shortId = "test-short",
        string uuid = "test-uuid", string hy2Password = "test-password", string hy2ServerName = "exitnode",
        string[]? hy2Certificate = null, string hy2ObfsPassword = "") => new()
    {
        Host = host, RealityPort = realityPort, Hy2Port = hy2Port, Sni = sni, RealityPublicKey = realityPublicKey,
        ShortId = shortId, Uuid = uuid, Hy2Password = hy2Password, Hy2ServerName = hy2ServerName,
        Hy2Certificate = hy2Certificate ?? ["-----BEGIN CERTIFICATE-----", "test-cert", "-----END CERTIFICATE-----"],
        Hy2ObfsPassword = hy2ObfsPassword
    };

    /// <summary>构造在指定时长后到期的会话；账号到期时间默认晚于会话。</summary>
    public static SessionResponse SessionExpiringIn(TimeSpan lifetime, string token = "test-session",
        NodeInfo? node = null, JsonElement? config = null, TimeSpan? accountLifetime = null) => new()
    {
        SessionToken = token, SessionExpiresAt = DateTimeOffset.UtcNow.Add(lifetime),
        AccountExpiresAt = DateTimeOffset.UtcNow.Add(accountLifetime ?? TimeSpan.FromDays(30)),
        SingboxConfig = config ?? Config, Node = node ?? Node()
    };
}
