using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using WinClient.Core.Client;
using Xunit;

namespace WinClient.Tests;

public sealed class AuthPinTests
{
    private static X509Certificate2 Certificate(ECDsa key) =>
        new CertificateRequest("CN=pin-test", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));

    [Fact]
    public void ComputedPinMatchesPublicKeyDigest()
    {
        using var key = ECDsa.Create();
        using var certificate = Certificate(key);
        var expected = Convert.ToBase64String(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));
        var actual = ClientSettings.ComputeSpkiSha256(certificate);
        Assert.Equal(expected, actual);
        Assert.Equal(44, actual.Length);
    }

    [Fact]
    public void SamePublicKeyIgnoresChainAndNameErrors()
    {
        using var key = ECDsa.Create();
        using var original = Certificate(key);
        using var renewed = Certificate(key);
        using var request = new HttpRequestMessage();
        var validate = ClientSettings.PinValidator(ClientSettings.ComputeSpkiSha256(original));
        Assert.True(validate(request, renewed, null,
            SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void DifferentKeyRejectedEvenWithoutPolicyErrors()
    {
        using var key = ECDsa.Create();
        using var otherKey = ECDsa.Create();
        using var original = Certificate(key);
        using var other = Certificate(otherKey);
        using var request = new HttpRequestMessage();
        Assert.False(ClientSettings.PinValidator(ClientSettings.ComputeSpkiSha256(original))(
            request, other, null, SslPolicyErrors.None));
    }

    [Fact]
    public void MissingCertificateRejected()
    {
        using var request = new HttpRequestMessage();
        Assert.False(ClientSettings.PinValidator(Convert.ToBase64String(new byte[32]))(
            request, null, null, SslPolicyErrors.None));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64!")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")]
    public void InvalidOrMissingPinHasChineseError(string? pin)
    {
        using var directory = new TempDirectory();
        var config = new Dictionary<string, string> { ["server_url"] = "https://192.0.2.1:8443" };
        if (pin is not null) config["server_spki_sha256"] = pin;
        File.WriteAllText(Path.Combine(directory.Path, "server.json"), JsonSerializer.Serialize(config));
        Assert.Contains("证书指纹", Assert.Throws<InvalidDataException>(() => ClientSettings.Load(directory.Path)).Message);
    }

    [Fact]
    public void ValidPinLoadsAndCreatesAuthClient()
    {
        using var directory = new TempDirectory();
        using var key = ECDsa.Create();
        using var certificate = Certificate(key);
        var pin = ClientSettings.ComputeSpkiSha256(certificate);
        const string url = "https://192.0.2.1:8443";
        File.WriteAllText(Path.Combine(directory.Path, "server.json"),
            JsonSerializer.Serialize(new { server_url = url, server_spki_sha256 = pin }));
        var settings = ClientSettings.Load(directory.Path)!;
        Assert.Equal(pin, settings.ServerSpkiSha256);
        using var http = settings.CreateAuthHttpClient();
        Assert.Equal(new Uri(url), http.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(15), http.Timeout);
    }
}
