using System.Security.Cryptography;

namespace WinClient.Core.Update;

public static class TrustedPublisher
{
    public const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERflJ30N+jSig1rioy/ZjqfjhuI+h
        5535snI5mSnafsfg5YacWoYxUK913+NODAa9MTjyasVRu8LwggI1smcjkw==
        -----END PUBLIC KEY-----
        """;
    public static ECDsa CreateKey()
    {
        var key = ECDsa.Create();
        try { key.ImportFromPem(PublicKeyPem); return key; }
        catch { key.Dispose(); throw; }
    }
}
