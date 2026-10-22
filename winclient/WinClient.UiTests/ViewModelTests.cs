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
