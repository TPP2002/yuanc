using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.Tests;

public sealed partial class UpdateTests
{
    [Fact]
    public void PlannerProtectsCurrentPreviousAndPendingAndIgnoresOutsideNames()
    {
        var root = Path.GetFullPath("app");
        var dirs = new[] { "0.1.0", "0.2.0", "1.0.0", "2.0.0", "current", "not-version" }.Select(v => Path.Combine(root, v)).ToArray();
        var plan = UpdatePlanner.Plan(root, Path.Combine(root, "1.0.0"), "2.0.0", dirs);
        Assert.Equal(Path.Combine(root, "2.0.0", "YuanC-Client.exe"), plan.TargetExe);
        Assert.Equal(new[] { Path.Combine(root, "0.1.0"), Path.Combine(root, "0.2.0") }, plan.DeleteDirectories);
        var pending = new UpdatePending(Path.Combine(root, "0.1.0", "YuanC-Client.exe"), "0.1.0", plan.TargetExe, "2.0.0", DateTimeOffset.UtcNow);
        plan = UpdatePlanner.Plan(root, Path.Combine(root, "1.0.0"), "2.0.0", dirs.Append(Path.GetFullPath("outside/3.0.0")), pending);
        Assert.Equal(new[] { Path.Combine(root, "0.2.0") }, plan.DeleteDirectories);
        plan = UpdatePlanner.Plan(root, Path.Combine(root, "2.0.0"), "2.0.0", dirs);
        Assert.Contains(Path.Combine(root, "1.0.0"), plan.KeepDirectories);
        Assert.DoesNotContain(plan.DeleteDirectories, d => d.EndsWith("current") || d.Contains("outside"));
    }
    [Fact]
    public void StoreRoundTripCorruptionAndAtomicWrites()
    {
        using var temp = new TempDirectory();
        var store = new UpdateStore(temp.Path);
        Assert.Null(store.ReadPending());
        var pending = new UpdatePending(Path.GetFullPath("app/0.1.0/YuanC-Client.exe"), "0.1.0",
            Path.GetFullPath("app/1.0.0/YuanC-Client.exe"), "1.0.0", DateTimeOffset.UtcNow);
        store.WritePending(pending); Assert.Equal(pending, store.ReadPending());
        store.MarkBad("1.0.0"); Assert.True(store.IsBad("1.0.0"));
        store.AppendHistory("1.0.0", "rolled_back", DateTimeOffset.UtcNow, "新版未响应，已恢复旧版。");
        Assert.Equal("rolled_back", Assert.Single(store.ReadHistory()).Status);
        File.AppendAllText(Path.Combine(temp.Path, "history.jsonl"), "{broken\n");
        Assert.Single(store.ReadHistory());
        File.WriteAllText(store.PendingPath, "{broken"); Assert.Null(store.ReadPending());
        Assert.True(store.HasPending);
        store.DeletePending(); Assert.False(store.HasPending);
        Assert.Empty(Directory.GetFiles(temp.Path, "*.tmp", SearchOption.AllDirectories));
        Assert.Throws<InvalidDataException>(() => store.MarkBad("../outside"));
    }
    internal static readonly byte[] Payload = Encoding.UTF8.GetBytes("test payload, not a real client");
    internal static byte[] ManifestBytes(string version = "1.0.0") => JsonSerializer.SerializeToUtf8Bytes(new
    {
        product = "YuanC-Client", version, file = $"YuanC-Client-{version}.exe",
        sha256 = Convert.ToHexString(SHA256.HashData(Payload)).ToLowerInvariant(), size = Payload.Length,
        built_at = "2026-10-22T00:00:00+00:00", min_service_version = "0.1.0"
    });

    [Fact]
    public void ManifestStrictFieldsAndUnknownExtension()
    {
        var raw = ManifestBytes();
        Assert.Equal("1.0.0", UpdateManifest.Parse(raw).Version);
        var value = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(raw)!;
        foreach (var name in value.Keys)
        {
            var missing = new Dictionary<string, JsonElement>(value); missing.Remove(name);
            Assert.Throws<InvalidDataException>(() => UpdateManifest.Parse(JsonSerializer.SerializeToUtf8Bytes(missing)));
        }
        foreach (var (name, replacement) in new[] { ("file", "\"YuanC-Client-2.0.0.exe\""),
            ("sha256", "\"" + new string('A', 64) + "\""), ("sha256", "\"abc\""), ("size", "-1"),
            ("built_at", "\"yesterday\""), ("product", "\"other\"") })
        {
            var bad = new Dictionary<string, JsonElement>(value) { [name] = JsonSerializer.Deserialize<JsonElement>(replacement) };
            Assert.Throws<InvalidDataException>(() => UpdateManifest.Parse(JsonSerializer.SerializeToUtf8Bytes(bad)));
        }
        value["extension"] = JsonSerializer.Deserialize<JsonElement>("true");
        Assert.Equal("1.0.0", UpdateManifest.Parse(JsonSerializer.SerializeToUtf8Bytes(value)).Version);
    }
    [Theory]
    [InlineData("1.2.10", "1.2.9", 1)]
    [InlineData("1.0.0-rc1", "1.0.0", -1)]
    [InlineData("1.0.0-rc.10", "1.0.0-rc.2", 1)]
    [InlineData("1.0.0", "1.0.0", 0)]
    public void VersionsCompareNumerically(string a, string b, int expected) =>
        Assert.Equal(expected, Math.Sign(new UpdateVersion(a).CompareTo(new UpdateVersion(b))));

    [Theory]
    [InlineData("1.2")]
    [InlineData("1.2.3+build")]
    [InlineData("1.2.3-")]
    [InlineData("../1.2.3")]
    [InlineData("1.2.3\n")]
    public void InvalidVersionRejected(string value) => Assert.Throws<InvalidDataException>(() => new UpdateVersion(value));

    [Fact]
    public void GeneratedSignaturesTamperAndWrongKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var raw = ManifestBytes();
        var signature = key.SignData(raw, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var manifest = UpdateVerifier.VerifyManifest(raw, signature, key);
        UpdateVerifier.VerifyPayload(new MemoryStream(Payload), manifest);
        Assert.Throws<InvalidDataException>(() => UpdateVerifier.VerifyManifest(raw, signature, other));
        raw[0] ^= 1;
        Assert.Throws<InvalidDataException>(() => UpdateVerifier.VerifyManifest(raw, signature, key));
        Assert.Throws<InvalidDataException>(() => UpdateVerifier.VerifyPayload(new MemoryStream(Payload[..^1]), manifest));
        var bad = (byte[])Payload.Clone(); bad[0] ^= 1;
        Assert.Throws<InvalidDataException>(() => UpdateVerifier.VerifyPayload(new MemoryStream(bad), manifest));
    }

    [Fact]
    public void PythonFixtureVerifiesInDotnet()
    {
        var root = Path.Combine(HostingTests.RepositoryRoot(), "winclient", "WinClient.Tests", "Fixtures", "update");
        using var key = ECDsa.Create(); key.ImportFromPem(File.ReadAllText(Path.Combine(root, "test-public-key.pem")));
        var path = Path.Combine(root, "YuanC-Client-9.9.9.manifest.json");
        var manifest = UpdateVerifier.VerifyManifest(File.ReadAllBytes(path), File.ReadAllBytes(path + ".sig"), key);
        Assert.Equal("9.9.9", manifest.Version);
        UpdateVerifier.VerifyPayload(new MemoryStream(Payload), manifest);
    }
}
