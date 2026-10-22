using System.Windows;
using System.Windows.Media;
using System.Windows.Controls.Primitives;
using System.Windows.Shapes;
using WinClient.App.Themes;
using WinClient.App.Controls;
using WinClient.App.Presentation;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ThemeAndMotionTests(UiThreadFixture ui)
{
    private void OnSta(Action action) => ui.Invoke(action);

    [Fact]
    public void 开关使用独立可变位移且关动画时立即就位() => OnSta(() =>
    {
        var toggle = new ToggleButton { IsChecked = true };
        foreach (var name in new[] { "Base", "Glyphs", "Controls" })
            toggle.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/WinClient.App;component/Themes/{name}.xaml", UriKind.Relative) });
        ThemeManager.Apply(toggle.Resources, ThemeKind.Light);
        toggle.Style = (Style)toggle.FindResource("Yc.Switch");
        MotionSettings.Override = false;
        try
        {
            toggle.ApplyTemplate(); toggle.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent));
            var thumb = Assert.IsType<Ellipse>(toggle.Template.FindName("Thumb", toggle));
            var transform = Assert.IsType<TranslateTransform>(thumb.RenderTransform);
            Assert.False(transform.IsFrozen); Assert.Equal(18, transform.X);
            toggle.IsChecked = false; Assert.Equal(0, transform.X);
            MotionSettings.Override = true;
            MotionSettings.Override = false;
            Assert.Equal(0, transform.X);
        }
        finally
        {
            toggle.RaiseEvent(new RoutedEventArgs(FrameworkElement.UnloadedEvent));
            MotionSettings.Override = null;
        }
    });

    [Fact]
    public void 两套主题键相同且完整() => OnSta(() =>
    {
        var light = new ResourceDictionary(); ThemeManager.Apply(light, ThemeKind.Light);
        var dark = new ResourceDictionary(); ThemeManager.Apply(dark, ThemeKind.Dark);
        var keys = light.MergedDictionaries.Single().Keys.Cast<string>().Order().ToArray();
        Assert.Equal(keys, dark.MergedDictionaries.Single().Keys.Cast<string>().Order().ToArray());
        foreach (var role in new[] { "Bg", "Surface", "Surface2", "Surface3", "Line", "LineStrong", "CtrlBorder", "Text", "Text2", "Text3", "Ok", "OkBg", "Warn", "WarnBg", "Bad", "BadBg", "Info", "InfoBg", "N", "NBg", "Action", "ActionText", "ActionHover", "ActionPress", "Focus" })
        { Assert.Contains("Yc." + role, keys); Assert.Contains("Yc.Color." + role, keys); }
        foreach (var tone in new[] { "Info", "Warn", "Ok", "Bad", "N" })
        {
            Assert.Contains("Yc.Spec." + tone, keys);
            var brush = Assert.IsType<LinearGradientBrush>(light["Yc.Spec." + tone]);
            Assert.Equal(GradientSpreadMethod.Repeat, brush.SpreadMethod);
            Assert.Equal(new Point(0, 0), brush.StartPoint); Assert.Equal(new Point(1, 0), brush.EndPoint);
            Assert.Equal(new[] { 0d, .333, .667, 1 }, brush.GradientStops.Select(s => s.Offset));
            Assert.Equal(brush.GradientStops[0].Color, brush.GradientStops[3].Color);
        }
        Assert.Contains("Yc.Shadow", keys);
    });

    [Fact]
    public void 换主题会替换原字典() => OnSta(() =>
    {
        var target = new ResourceDictionary();
        var other = new ResourceDictionary(); target.MergedDictionaries.Add(other);
        ThemeManager.Apply(target, ThemeKind.Light);
        Assert.Equal(ColorConverter.ConvertFromString("#FBFBFA"), ((SolidColorBrush)target["Yc.Bg"]).Color);
        ThemeManager.Apply(target, ThemeKind.Dark);
        Assert.Equal(ColorConverter.ConvertFromString("#0D0D0E"), ((SolidColorBrush)target["Yc.Bg"]).Color);
        Assert.Equal(2, target.MergedDictionaries.Count); Assert.Same(other, target.MergedDictionaries[0]);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void 动效门可覆盖(bool enabled) => OnSta(() =>
    {
        try
        {
            MotionSettings.Override = enabled;
            Assert.Equal(enabled, MotionSettings.Enabled);
            var tile = new StatusTile { Flow = Flow.Forward };
            Assert.Equal(enabled, tile.IsFlowing);
            tile.Flow = Flow.None;
            Assert.False(tile.IsFlowing);
        }
        finally { MotionSettings.Override = null; }
    });
}
