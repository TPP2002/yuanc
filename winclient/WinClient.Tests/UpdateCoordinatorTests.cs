using System.Security.Cryptography;
using WinClient.Core.Client;
using WinClient.Core.State;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.Tests;

public sealed class UpdateCoordinatorTests
{
    [Theory]
    [InlineData(false, "1.0.0", false, false, "skipped")]
    [InlineData(true, "0.1.0", false, false, "skipped")]
    [InlineData(true, "1.0.0", true, false, "skipped")]
    [InlineData(true, "1.0.0", false, true, "failed")]
    [InlineData(true, "1.0.0", false, false, "staged")]
    public async Task GatesVerificationAndPending(bool connected, string version, bool bad, bool tamper, string expected)
    {
        using var temp = new TempDirectory();
        using var source = new Source(version, tamper);
        var store = new UpdateStore(Path.Combine(temp.Path, "updates"));
        if (bad) store.MarkBad(version);
        var appRoot = Path.Combine(temp.Path, "app");
        var old = UpdatePlanner.Executable(appRoot, "0.1.0");
        Directory.CreateDirectory(Path.GetDirectoryName(old)!); File.WriteAllText(old, "old");
        string? launched = null;
        var at = DateTimeOffset.Parse("2026-10-22T00:00:00Z");
        using var coordinator = new UpdateCoordinator(source, store,
            () => new(connected ? ConnectionState.Connected : ConnectionState.Disconnected, "", "", true),
            () => at, "0.1.0", appRoot: appRoot, currentExe: old, launch: p => launched = p, publicKey: source.PublicKey);
        await coordinator.CheckNowAsync();
        Assert.Equal(expected, store.ReadHistory().Last().Status);
        Assert.Equal(connected ? 1 : 0, source.Requests);
        Assert.True(File.Exists(old));
        if (expected == "staged")
        {
            var pending = Assert.IsType<UpdatePending>(store.ReadPending());
            Assert.Equal(old, pending.OldExe); Assert.Equal("0.1.0", pending.OldVersion);
            Assert.Equal("1.0.0", pending.NewVersion); Assert.Equal(at, pending.StartedAt);
            Assert.Equal(UpdateTests.Payload, File.ReadAllBytes(pending.NewExe));
            Assert.Equal(UpdateTests.Payload, File.ReadAllBytes(Path.Combine(store.Incoming, "1.0.0.exe")));
            Assert.Equal(old, launched); Assert.Equal("applying", coordinator.Status.Stage);
        }
        else
        {
            Assert.Null(launched); Assert.False(store.HasPending);
            Assert.Empty(Directory.Exists(store.Incoming) ? Directory.GetFiles(store.Incoming) : []);
        }
    }

    [Fact]
    public async Task ClockScheduleAndReentryAreBounded()
    {
        using var temp = new TempDirectory(); using var source = new Source("0.1.0", false);
        var wait = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.Wait = wait.Task;
        var now = DateTimeOffset.UtcNow;
        using var coordinator = new UpdateCoordinator(source, new UpdateStore(temp.Path),
            () => new(ConnectionState.Connected, "", "", true), () => now, "0.1.0");
        await coordinator.TickAsync(); Assert.Equal(0, source.Requests);
        now += TimeSpan.FromMinutes(5);
        var first = coordinator.TickAsync();
        await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = await coordinator.CheckNowAsync().WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal("checking", second.Stage); Assert.Equal(1, source.Requests);
        wait.SetResult(); await first;
        await coordinator.TickAsync(); Assert.Equal(1, source.Requests);
        now += TimeSpan.FromHours(6);
        await coordinator.TickAsync(); Assert.Equal(2, source.Requests);
    }

    internal sealed class Source(string version, bool tamper) : IUpdateSource, IDisposable
    {
        private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public int Requests;
        public Task? Wait;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ECDsa PublicKey() { var result = ECDsa.Create(); result.ImportParameters(key.ExportParameters(false)); return result; }
        public async Task<UpdateIndex?> LatestAsync(CancellationToken token)
        {
            Interlocked.Increment(ref Requests); Entered.TrySetResult();
            if (Wait is not null) await Wait.WaitAsync(token);
            var manifest = UpdateManifest.Parse(UpdateTests.ManifestBytes(version));
            return new(version, manifest.File, $"YuanC-Client-{version}.manifest.json", $"YuanC-Client-{version}.manifest.json.sig", manifest.Size, manifest.Sha256);
        }
        public Task<byte[]> ReadAsync(string name, int maximumBytes, CancellationToken token)
        {
            var raw = UpdateTests.ManifestBytes(version);
            if (!name.EndsWith(".sig")) return Task.FromResult(raw);
            var signature = key.SignData(raw, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (tamper) signature[^1] ^= 1;
            return Task.FromResult(signature);
        }
        public Task DownloadAsync(UpdateManifest manifest, string temporaryFile, CancellationToken token)
        { Directory.CreateDirectory(Path.GetDirectoryName(temporaryFile)!); return File.WriteAllBytesAsync(temporaryFile, UpdateTests.Payload, token); }
        public void Dispose() => key.Dispose();
    }
}
