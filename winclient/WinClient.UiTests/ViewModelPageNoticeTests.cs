using WinClient.App;
using WinClient.App.Presentation;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ViewModelPageNoticeTests(UiThreadFixture ui)
{
    private static MainViewModel Model(string message, string serviceVersion)
    {
        var model = new MainViewModel(() => null, () => null);
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", message, false) { ServiceVersion = serviceVersion },
            ServiceAvailability.Ready, connectionUsable: true);
        return model;
    }

    [Fact]
    public void NoticeEmptyOnConnectPage() => ui.Invoke(() =>
    {
        using var model = Model("节点暂时连不上", ControlSnapshot.CurrentVersion);
        Assert.Equal(PageKind.Connect, model.CurrentPage);
        Assert.Equal("节点暂时连不上", model.Message);
        Assert.Equal("", model.PageNoticeText);
    });

    [Theory]
    [InlineData(PageKind.Routing)]
    [InlineData(PageKind.Environment)]
    [InlineData(PageKind.Account)]
    [InlineData(PageKind.Update)]
    public void NoticeMirrorsMessageOnOtherPages(PageKind page) => ui.Invoke(() =>
    {
        using var model = Model("节点暂时连不上", ControlSnapshot.CurrentVersion);
        model.CurrentPage = page;
        Assert.Equal("节点暂时连不上", model.PageNoticeText);
        Assert.Equal(model.Message.Trim(), model.PageNoticeText);
    });

    [Fact]
    public void NoticeEmptyWhenNoMessage() => ui.Invoke(() =>
    {
        using var model = Model("", ControlSnapshot.CurrentVersion);
        model.CurrentPage = PageKind.Update;
        Assert.Equal("", model.Message);
        Assert.Equal("", model.PageNoticeText);
    });

    [Fact]
    public void NoticeCarriesVersionReminderWithoutLeadingSpace() => ui.Invoke(() =>
    {
        using var model = Model("", "9.9.9");
        model.CurrentPage = PageKind.Routing;
        Assert.StartsWith(" 后台已更新到 9.9.9", model.Message);
        Assert.StartsWith("后台已更新到 9.9.9", model.PageNoticeText);
        Assert.Equal(model.Message.Trim(), model.PageNoticeText);
    });

    [Fact]
    public void SwitchingPageRaisesNoticeChange() => ui.Invoke(() =>
    {
        using var model = Model("节点暂时连不上", ControlSnapshot.CurrentVersion);
        var notified = new List<string?>();
        model.PropertyChanged += (_, args) => notified.Add(args.PropertyName);
        model.CurrentPage = PageKind.Account;
        Assert.Contains(nameof(MainViewModel.PageNoticeText), notified);
        Assert.Equal("节点暂时连不上", model.PageNoticeText);
        notified.Clear();
        model.CurrentPage = PageKind.Connect;
        Assert.Contains(nameof(MainViewModel.PageNoticeText), notified);
        Assert.Equal("", model.PageNoticeText);
    });

    [Fact]
    public void FailedOperationOnAccountPageShowsNotice() => ui.Invoke(() =>
    {
        using var model = Model("", ControlSnapshot.CurrentVersion);
        model.CurrentPage = PageKind.Account;
        Assert.Equal("", model.PageNoticeText);
        var notified = new List<string?>();
        model.PropertyChanged += (_, args) => notified.Add(args.PropertyName);
        model.Code = "ABCD-1234";
        model.RedeemCommand.Execute(null);
        Assert.False(model.IsBusy);
        Assert.Equal("操作未完成，请检查后台服务或联系管理员。", model.PageNoticeText);
        Assert.Contains(nameof(MainViewModel.PageNoticeText), notified);
    });
}