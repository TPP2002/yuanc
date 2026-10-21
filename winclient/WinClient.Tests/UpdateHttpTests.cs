using System.Net;
using System.Net.Http.Headers;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.Tests;

public sealed class UpdateHttpTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ResumeOrRestartWithoutAppendingAFullResponse(bool partial)
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "client.part");
        File.WriteAllBytes(path, UpdateTests.Payload[..5]);
        using var source = new HttpUpdateSource(new AuthTests.Handler(request =>
        {
            Assert.Equal("http://198.18.255.1/winclient/YuanC-Client-1.0.0.exe", request.RequestUri!.AbsoluteUri);
            Assert.Equal("bytes=5-", request.Headers.Range!.ToString());
            var response = new HttpResponseMessage(partial ? HttpStatusCode.PartialContent : HttpStatusCode.OK)
            { Content = new ByteArrayContent(partial ? UpdateTests.Payload[5..] : UpdateTests.Payload) };
            if (partial) response.Content.Headers.ContentRange = new ContentRangeHeaderValue(5, 30, 31);
            return response;
        }));
        await source.DownloadAsync(UpdateManifest.Parse(UpdateTests.ManifestBytes()), path, CancellationToken.None);
        Assert.Equal(UpdateTests.Payload, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task RedirectOversizeAndTraversalAreRejected()
    {
        using var source = new HttpUpdateSource(new AuthTests.Handler(_ => new(HttpStatusCode.Redirect)));
        await Assert.ThrowsAsync<InvalidDataException>(() => source.ReadAsync("latest.json", 65536, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => source.ReadAsync("../secret", 65536, CancellationToken.None));
        using var large = new HttpUpdateSource(new AuthTests.Handler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[65537]) }));
        await Assert.ThrowsAsync<InvalidDataException>(() => large.ReadAsync("latest.json", 65536, CancellationToken.None));
    }
}
