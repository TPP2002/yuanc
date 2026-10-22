using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using WinClient.App;
using WinClient.App.Presentation;
using WinClient.App.Themes;
using WinClient.App.Views;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using WinClient.Core.Update;
using Xunit;
using Xunit.Abstractions;

namespace WinClient.UiTests;

[Collection("界面线程")]
public sealed class RenderTests(UiThreadFixture ui, ITestOutputHelper output)
{
    private sealed record Preview(string Name, ControlSnapshot Snapshot, ServiceAvailability Availability = ServiceAvailability.Ready);
    private sealed record Bounds(double X, double Y, double W, double H);

    private static ControlSnapshot Snapshot(ConnectionState state, string message = "") => new(state, "无法连接后台服务", message,
        state is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting)
    { Mode = "自用模式", ServiceVersion = "1.3.0" };

    private static Preview[] Cases() =>
    [
        new("need-install", Snapshot(ConnectionState.Disconnected) with { ServiceVersion = "", Mode = "未配置" }, ServiceAvailability.NeedInstall),
        new("need-repair", Snapshot(ConnectionState.Disconnected), ServiceAvailability.NeedRepair),
        new("unavailable", Snapshot(ConnectionState.Disconnected, "无法连接后台服务,请重启电脑或联系管理员"), ServiceAvailability.Unavailable),
        new("disconnected", Snapshot(ConnectionState.Disconnected)),
        new("connecting", Snapshot(ConnectionState.Connecting, "正在套用断网保护、启动隧道…") with { ExitStatus = "核验中" }),
        new("connected", Snapshot(ConnectionState.Connected, "虚拟网卡已就绪。") with
        { ExitStatus = "已核验", ExitIp = "203.0.113.9", GuardStatus = "正常", SelfCheckStatus = "8 项通过", EnvironmentStatus = "已切换到澳洲时区与浏览器策略" }),
        new("connected-warning", Snapshot(ConnectionState.Connected, "断网保护未能重新套用:请在 Windows 安全中心开启防火墙或联系管理员。") with
        { ExitStatus = "已核验", ExitIp = "203.0.113.9", GuardStatus = "断网保护未能重新套用:系统防火墙已被关闭或被策略覆盖,隧道保持但失去断网兜底", SelfCheckStatus = "8 项通过" }),
        new("reconnecting", Snapshot(ConnectionState.Reconnecting, "鉴权服务器暂时连不上,30 秒后再试;断网保护保持,期间不会漏流量") with { Mode = "分发模式", ExitStatus = "无法核验", GuardStatus = "正常" }),
        new("needs-login", Snapshot(ConnectionState.NeedsLogin, "账号或会话已到期;断网保护保持,先兑换新的邀请码再连接") with { ProtectionActive = true, Mode = "分发模式" }),
        new("needs-manual", Snapshot(ConnectionState.NeedsManual, "系统防火墙被关闭或被策略覆盖,已拒绝连接;请开启防火墙后重新连接。") with { ProtectionActive = true })
    ];

    [Fact]
    public void 浅深二十八张截图与主按钮位置固定()
    {
        if (!System.Environment.UserInteractive)
        {
            output.WriteLine("跳过渲染：Environment.UserInteractive 为 false，当前不是交互式用户会话。");
            return;
        }
        ui.Invoke(() =>
        {
            var directory = Path.Combine(RepositoryRoot(), "build", "ui-shots");
            Directory.CreateDirectory(directory);
            var resources = Application.Current.Resources;
            foreach (var name in new[] { "Base", "Glyphs", "Controls" })
                resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/WinClient.App;component/Themes/{name}.xaml", UriKind.Relative) });
            var bounds = new Dictionary<string, Bounds>();
            Bounds? expected = null;
            var count = 0;
            MotionSettings.Override = false;
            try
            {
                foreach (var theme in new[] { ThemeKind.Light, ThemeKind.Dark })
                {
                    ThemeManager.Apply(resources, theme);
                    var suffix = theme == ThemeKind.Dark ? "-dark" : "";
                    foreach (var preview in Cases())
                    {
                        using var model = Model(preview.Snapshot, preview.Availability);
                        var shell = Arrange(model);
                        try
                        {
                            var button = Descendants(shell).OfType<Button>().Single(element => element.Name == "PrimaryButton");
                            Assert.Equal(model.ConnectLabel, button.Content);
                            var label = Descendants(button).OfType<TextBlock>().Single(element => element.Text == model.ConnectLabel);
                            Assert.NotEqual(Assert.IsType<SolidColorBrush>(button.Background).Color, Assert.IsType<SolidColorBrush>(label.Foreground).Color);
                            Assert.True(label.ActualWidth > 0 && label.ActualWidth <= button.ActualWidth, "主按钮文字必须可见且不超出按钮");
                            var point = button.TranslatePoint(new Point(), shell);
                            var actual = new Bounds(point.X, point.Y, button.ActualWidth, button.ActualHeight);
                            expected ??= actual;
                            Assert.Equal(expected, actual);
                            Assert.Equal(144, actual.W); Assert.Equal(40, actual.H);
                            bounds[preview.Name] = actual;
                            WritePng(shell, Path.Combine(directory, "connect-" + preview.Name + suffix + ".png")); count++;
                        }
                        finally { Unload(shell); }
                    }
                    foreach (var page in new[] { PageKind.Routing, PageKind.Environment, PageKind.Account, PageKind.Update })
                    {
                        var snapshot = Snapshot(ConnectionState.Disconnected) with
                        {
                            RoutingApps = [@"C:\Users\Me\AppData\Local\Discord\app-1.0.9165\Discord.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe"],
                            SelfCheckStatus = "8 项通过", EnvironmentStatus = "已切换到澳洲时区与浏览器策略",
                            Update = new UpdateStatus("idle", Message: "已是最新", CheckedAt: new DateTimeOffset(2026, 10, 22, 9, 12, 0, TimeSpan.FromHours(8)))
                        };
                        using var model = Model(snapshot, ServiceAvailability.Ready);
                        model.CurrentPage = page;
                        if (page == PageKind.Environment) model.ApplySelfCheckJson(SelfCheckReport());
                        var shell = Arrange(model);
                        try { WritePng(shell, Path.Combine(directory, "page-" + page.ToString().ToLowerInvariant() + suffix + ".png")); count++; }
                        finally { Unload(shell); }
                    }
                }
                Assert.Equal(28, count); Assert.Equal(10, bounds.Count);
                File.WriteAllText(Path.Combine(directory, "primary-button.json"), JsonSerializer.Serialize(bounds,
                    new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true }));
                output.WriteLine("已渲染 28 张 PNG；浅深主题十种连接状态下主按钮坐标与尺寸完全相同。");
            }
            finally { MotionSettings.Override = null; }
        });
    }

    private static MainViewModel Model(ControlSnapshot snapshot, ServiceAvailability availability)
    {
        var model = new MainViewModel(() => throw new InvalidOperationException("渲染不允许弹出对话框"), () => throw new InvalidOperationException("渲染不允许选择程序"));
        model.ApplyPreview(snapshot, availability);
        return model;
    }
    private static MainShell Arrange(MainViewModel model)
    {
        var shell = new MainShell { DataContext = model, Width = 880, Height = 600 };
        shell.Measure(new Size(880, 600)); shell.Arrange(new Rect(0, 0, 880, 600)); shell.UpdateLayout();
        foreach (var element in Descendants(shell).OfType<FrameworkElement>().Prepend(shell).ToArray()) element.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent, element));
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
        shell.UpdateLayout();
        return shell;
    }
    private static void Unload(MainShell shell)
    {
        foreach (var element in Descendants(shell).OfType<FrameworkElement>().Prepend(shell).ToArray()) element.RaiseEvent(new RoutedEventArgs(FrameworkElement.UnloadedEvent, element));
        shell.DataContext = null;
    }
    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i); yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }
    private static void WritePng(MainShell shell, string path)
    {
        var bitmap = new RenderTargetBitmap(880, 600, 96, 96, PixelFormats.Pbgra32); bitmap.Render(shell);
        var pixels = new int[880 * 600]; bitmap.CopyPixels(pixels, 880 * 4, 0);
        Assert.True(pixels.Any(pixel => pixel != pixels[0]), "截图不得为纯色");
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(path); encoder.Save(file);
    }
    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "winclient", "WinClient.sln"))) return directory.FullName;
        throw new DirectoryNotFoundException("未找到仓库根目录");
    }
    private static string SelfCheckReport() => JsonSerializer.Serialize(new
    {
        checked_at = "2026-10-22T14:32:00+08:00", summary = "8 项通过",
        items = new[] { "出口归属澳洲", "出口与节点一致", "系统时区", "自动时区已关", "Chrome 策略", "Edge 策略", "配置无直连路径", "IPv6 已封堵" }
            .Select((name, index) => new { id = index.ToString(), name, result = "通过", detail = "" }).ToArray()
    });
}
