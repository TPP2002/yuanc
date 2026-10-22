using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public class BrowserProfilePlannerTests
{
    [Fact]
    public void 首选项仅在配置不存在时写入()
    {
        var script = BrowserProfilePlanner.Script();
        foreach (var value in new[] { "intl", "accept_languages", "en-AU,en", "webrtc", "ip_handling_policy", "default_public_interface_only" })
            Assert.Contains(value, script);
        Assert.True(script.IndexOf("Test-Path -LiteralPath $prefFile", StringComparison.Ordinal) < script.IndexOf("WriteAllText", StringComparison.Ordinal));
    }

    [Fact]
    public void 查找浏览器并创建独立快捷方式()
    {
        var script = BrowserProfilePlanner.Script();
        foreach (var value in new[] { "--user-data-dir=", "--disable-quic", "--no-first-run", "--no-default-browser-check", "WScript.Shell", "CreateShortcut", "澳洲专用 ", ".lnk", "chrome.exe", "msedge.exe", "App Paths", "HKLM:", "HKCU:" })
            Assert.Contains(value, script);
    }

    [Fact]
    public void 不删除数据不修改注册表且以结果退出()
    {
        var script = BrowserProfilePlanner.Script();
        foreach (var value in new[] { "Remove-Item", "-Recurse", "Set-ItemProperty", "New-ItemProperty", "Policies" })
            Assert.DoesNotContain(value, script);
        var resultLine = script.Split('\n').Single(line => line.Contains("ConvertTo-Json -Compress"));
        Assert.Equal("exit 0", script[(script.IndexOf(resultLine, StringComparison.Ordinal) + resultLine.Length)..].Trim());
    }

    [Theory]
    [InlineData("{\"created\":[\"Chrome\",\"Edge\"],\"missing\":[],\"kept\":[]}", "澳洲专用 Chrome", "澳洲专用 Edge", "只登录目标平台账号")]
    [InlineData("{\"created\":[\"Chrome\"],\"missing\":[\"Edge\"],\"kept\":[\"Chrome\"]}", "澳洲专用 Chrome", "未找到 Edge", "保留原设置")]
    [InlineData("{\"created\":\"Chrome\",\"missing\":\"Edge\",\"kept\":[]}", "澳洲专用 Chrome", "未找到 Edge", "只登录目标平台账号")]
    [InlineData("{\"created\":[],\"missing\":[\"Chrome\",\"Edge\"],\"kept\":[]}", "未找到 Chrome 或 Edge", "请先安装", "再试")]
    [InlineData(null, "未完成", "请联系管理员", "创建快捷方式")]
    [InlineData("", "未完成", "请联系管理员", "创建快捷方式")]
    [InlineData("not json", "未完成", "请联系管理员", "创建快捷方式")]
    [InlineData("{}", "未完成", "请联系管理员", "创建快捷方式")]
    [InlineData("提示\n{\"created\":\"Chrome\"}\n\n", "澳洲专用 Chrome", "只登录目标平台账号", "日常上网")]
    public void 解释最后一行结果(string? output, string first, string second, string third)
    {
        var message = BrowserProfilePlanner.Describe(output);
        Assert.Contains(first, message); Assert.Contains(second, message); Assert.Contains(third, message);
    }
}
