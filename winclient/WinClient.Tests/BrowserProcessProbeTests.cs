using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class BrowserProcessProbeTests
{
    [Fact]
    public void 系统浏览器探测只返回已知名称且不重复()
    {
        if (!OperatingSystem.IsWindows()) return;
        var browsers = new SystemBrowserProcessProbe().RunningBrowsers();
        Assert.NotNull(browsers);
        Assert.All(browsers, browser => Assert.Contains(browser, new[] { "Chrome", "Edge" }));
        Assert.Equal(browsers.Count, browsers.Distinct().Count());
    }
}
