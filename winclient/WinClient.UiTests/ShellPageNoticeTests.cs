using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using WinClient.App;
using WinClient.App.Presentation;
using WinClient.App.Themes;
using WinClient.App.Views;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ShellPageNoticeTests(UiThreadFixture ui)
{
    private static MainViewModel Model(string message, string serviceVersion)
    {
        var model = new MainViewModel(() => null, () => null);
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", message, false) { ServiceVersion = serviceVersion },
            ServiceAvailability.Ready, connectionUsable: true);
        return model;
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i); yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }

    // 照 RenderTests.Arrange 的做法把界面排好版(880×600,不开窗口),排完交给 check,最后卸掉。
    private static void WithShell(MainViewModel model, Action<MainShell> check)
    {
        var resources = Application.Current.Resources;
        foreach (var name in new[] { "Base", "Glyphs", "Controls" })
        {
            var merged = resources.MergedDictionaries.Any(item => item.Source is not null && item.Source.OriginalString.EndsWith("/" + name + ".xaml", StringComparison.Ordinal));
            if (!merged) resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/WinClient.App;component/Themes/{name}.xaml", UriKind.Relative) });
        }
        ThemeManager.Apply(resources, ThemeKind.Light);
        MotionSettings.Override = false;
        var shell = new MainShell { DataContext = model, Width = 880, Height = 600 };
        try
        {
            shell.Measure(new Size(880, 600)); shell.Arrange(new Rect(0, 0, 880, 600)); shell.UpdateLayout();
            foreach (var element in Descendants(shell).OfType<FrameworkElement>().Prepend(shell).ToArray())
                element.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent, element));
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
            shell.UpdateLayout();
            check(shell);
        }
        finally
        {
            foreach (var element in Descendants(shell).OfType<FrameworkElement>().Prepend(shell).ToArray())
                element.RaiseEvent(new RoutedEventArgs(FrameworkElement.UnloadedEvent, element));
            shell.DataContext = null;
            MotionSettings.Override = null;
        }
    }

    [Theory]
    [InlineData(PageKind.Routing)]
    [InlineData(PageKind.Environment)]
    [InlineData(PageKind.Account)]
    [InlineData(PageKind.Update)]
    public void NoticeDockedAtBottomOnOtherPages(PageKind page) => ui.Invoke(() =>
    {
        using var model = Model("节点暂时连不上", ControlSnapshot.CurrentVersion);
        model.CurrentPage = page;
        WithShell(model, shell =>
        {
            var notice = Descendants(shell).OfType<Border>().Single(element => element.Name == "PageNotice");
            var host = Descendants(shell).OfType<ContentControl>().Single(element => element.Name == "PageHost");
            Assert.Equal(Visibility.Visible, notice.Visibility);
            var noticeTop = notice.TranslatePoint(new Point(), shell);
            Assert.Equal(200, noticeTop.X, 3);
            Assert.Equal(680, notice.ActualWidth, 3);
            Assert.True(notice.ActualHeight > 0, "提示条要有高度");
            Assert.Equal(600, noticeTop.Y + notice.ActualHeight, 3);
            var hostTop = host.TranslatePoint(new Point(), shell);
            Assert.True(hostTop.Y + host.ActualHeight <= noticeTop.Y + 0.001, "页面内容不能压在提示条上");
            var text = Descendants(notice).OfType<TextBlock>().Single();
            Assert.Equal(model.PageNoticeText, text.Text);
            Assert.Equal("节点暂时连不上", text.Text);
        });
    });

    [Fact]
    public void NoticeCollapsedOnConnectPage() => ui.Invoke(() =>
    {
        using var model = Model("节点暂时连不上", ControlSnapshot.CurrentVersion);
        WithShell(model, shell =>
        {
            var notice = Descendants(shell).OfType<Border>().Single(element => element.Name == "PageNotice");
            var host = Descendants(shell).OfType<ContentControl>().Single(element => element.Name == "PageHost");
            Assert.Equal(PageKind.Connect, model.CurrentPage);
            Assert.Equal(Visibility.Collapsed, notice.Visibility);
            Assert.Equal(552, host.ActualHeight, 3);
        });
    });

    [Fact]
    public void NoticeCollapsedWithoutMessageKeepsPageArea() => ui.Invoke(() =>
    {
        using var model = Model("", ControlSnapshot.CurrentVersion);
        model.CurrentPage = PageKind.Update;
        WithShell(model, shell =>
        {
            var notice = Descendants(shell).OfType<Border>().Single(element => element.Name == "PageNotice");
            var host = Descendants(shell).OfType<ContentControl>().Single(element => element.Name == "PageHost");
            Assert.Equal(Visibility.Collapsed, notice.Visibility);
            Assert.Equal(552, host.ActualHeight, 3);
            Assert.Equal(616, host.ActualWidth, 3);
        });
    });

    [Fact]
    public void NoticeAppearsAfterFailedOperation() => ui.Invoke(() =>
    {
        using var model = Model("", ControlSnapshot.CurrentVersion);
        model.CurrentPage = PageKind.Account;
        WithShell(model, shell =>
        {
            var notice = Descendants(shell).OfType<Border>().Single(element => element.Name == "PageNotice");
            Assert.Equal(Visibility.Collapsed, notice.Visibility);
            model.Code = "ABCD-1234";
            model.RedeemCommand.Execute(null);
            shell.UpdateLayout();
            Assert.Equal(Visibility.Visible, notice.Visibility);
            var text = Descendants(notice).OfType<TextBlock>().Single();
            Assert.Equal("操作未完成，请检查后台服务或联系管理员。", text.Text);
            Assert.Equal(600, notice.TranslatePoint(new Point(), shell).Y + notice.ActualHeight, 3);
        });
    });
}