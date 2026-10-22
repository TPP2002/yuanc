using WinClient.App;
using WinClient.App.Presentation;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ViewModelTests(UiThreadFixture ui)
{
    [Fact]
    public void 浏览器复核无需后台且保留主消息() => ui.Invoke(() =>
    {
        string? received = null;
        using var model = new MainViewModel(() => null, () => null, null,
            html => { received = html; return @"C:\fake\verify.html"; });
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false)
            { RoutingMode = "apps", EnvironmentEnabled = false }, ServiceAvailability.Unavailable);
        var message = model.Message;
        Assert.True(model.OpenVerifyPageCommand.CanExecute(null));
        model.OpenVerifyPageAsync().GetAwaiter().GetResult();
        Assert.Contains("data-mode=\"apps\"", received);
        Assert.Contains("data-env=\"off\"", received);
        Assert.Contains(@"C:\fake\verify.html", model.VerifyPageMessage);
        Assert.Equal(message, model.Message);
        using var failed = new MainViewModel(() => null, () => null, null, _ => null);
        failed.OpenVerifyPageAsync().GetAwaiter().GetResult();
        Assert.Contains("未完成", failed.VerifyPageMessage);
    });

    [Fact]
    public void 专用浏览器无需后台且不修改主消息() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null,
            (_, _) => Task.FromResult<string?>("{\"created\":[\"Chrome\"],\"missing\":[\"Edge\"],\"kept\":[]}"));
        var message = model.Message;
        Assert.True(model.CreateBrowserProfileCommand.CanExecute(null));
        model.CreateBrowserProfileAsync().GetAwaiter().GetResult();
        Assert.Contains("澳洲专用 Chrome", model.BrowserProfileMessage);
        Assert.Contains("未找到 Edge", model.BrowserProfileMessage);
        Assert.Equal(message, model.Message);
        using var failed = new MainViewModel(() => null, () => null, (_, _) => Task.FromResult<string?>(null));
        failed.CreateBrowserProfileAsync().GetAwaiter().GetResult();
        Assert.Contains("未完成", failed.BrowserProfileMessage);
    });

    [Theory]
    [InlineData("通过", Tone.Ok, Glyph.Check, false)]
    [InlineData("未通过", Tone.Bad, Glyph.X, false)]
    [InlineData("跳过", Tone.N, Glyph.Ring, true)]
    [InlineData("无法核验", Tone.Warn, Glyph.Ask, false)]
    public void 自检明细解析并映射四种结果(string result, Tone tone, Glyph glyph, bool dim) => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.ApplySelfCheckJson(System.Text.Json.JsonSerializer.Serialize(new
        {
            checked_at = "2026-10-22T14:32:00+08:00", summary = "测试汇总",
            items = new[] { new { id = "timezone", name = "系统时区", result, detail = "检查明细" } }
        }));
        var item = Assert.Single(model.SelfCheckItems);
        Assert.Equal(1, item.Index); Assert.Equal("系统时区", item.Name); Assert.Equal("检查明细", item.Detail);
        Assert.Equal(new TileSpec(tone, glyph, Flow.None, Dim: dim), item.Tile);
        Assert.Equal("测试汇总", model.SelfCheckSummary); Assert.Equal("2026-10-22T14:32:00+08:00", model.SelfCheckCheckedAtText);
        model.ApplySelfCheckJson("{}"); Assert.Empty(model.SelfCheckItems);
        Assert.Equal("", model.SelfCheckSummary);
    });
    [Fact]
    public void 预览不建立连接且保留消息和版本() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => throw new Exception("不应弹出文件选择"), () => throw new Exception("不应选择程序"));
        var snapshot = new ControlSnapshot(ConnectionState.NeedsLogin, "需要重新登录", "会话已到期", true)
        { ServiceVersion = "1.3.0", Mode = "分发模式", Update = new UpdateStatus("checking", Message: "正在检查更新") };
        model.ApplyPreview(snapshot, ServiceAvailability.Ready);
        Assert.Equal("断开", model.ConnectLabel); Assert.True(model.Hero.ShowGoToAccount); Assert.False(model.CanUseConnection);
        Assert.Equal("版本 1.3.0", model.ServiceVersionText); Assert.Equal("分发模式", model.ModeText);
        Assert.Equal("会话已到期 后台已更新到 1.3.0，下次打开界面将使用新版", model.Message);
        Assert.True(model.IsUpdateInProgress);
        model.GoToAccountCommand.Execute(null); Assert.Equal(PageKind.Account, model.CurrentPage);
    });
}
