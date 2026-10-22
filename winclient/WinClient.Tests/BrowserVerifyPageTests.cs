using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public class BrowserVerifyPageTests
{
    [Fact]
    public void 包含完整页面与五项浏览器检查()
    {
        var html = BrowserVerifyPage.Html(new("global", true));
        foreach (var value in new[] { "lang=\"zh-CN\"", "Content-Security-Policy", "default-src 'none'", "connect-src https://1.1.1.1", "Australia/", "en-AU", "cdn-cgi/trace", "RTCPeerConnection", "geolocation", ".local", "172.19.0.", "重新检查" })
            Assert.Contains(value, html);
    }

    [Fact]
    public void 页面不引入外部资源或探测服务器()
    {
        var html = BrowserVerifyPage.Html(new("global", true));
        foreach (var value in new[] { "<script src", "<link ", "http://", "stun:", "turn:", "@import", "url(" })
            Assert.DoesNotContain(value, html);
    }

    [Theory]
    [InlineData("apps", false, "apps", "off")]
    [InlineData("global", true, "global", "on")]
    [InlineData("", false, "global", "off")]
    [InlineData("anything", true, "global", "on")]
    public void 上下文仅生成允许的属性值(string mode, bool enabled, string expectedMode, string expectedEnv)
    {
        var html = BrowserVerifyPage.Html(new(mode, enabled));
        Assert.Contains($"data-mode=\"{expectedMode}\"", html);
        Assert.Contains($"data-env=\"{expectedEnv}\"", html);
        Assert.DoesNotContain("anything", html);
    }

    [Fact]
    public void 文件名固定且脚本位于正文之后()
    {
        Assert.Equal("verify.html", BrowserVerifyPage.FileName);
        var html = BrowserVerifyPage.Html(new("global", true));
        Assert.True(html.IndexOf("<body", StringComparison.Ordinal) < html.IndexOf("<script>", StringComparison.Ordinal));
        Assert.Equal(2, html.Split("<script>").Length);
    }
}
