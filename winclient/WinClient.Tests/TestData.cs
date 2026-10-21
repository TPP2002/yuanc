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
}
