using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace WinClient.App.Themes;

public static class EntranceMotion
{
    private static readonly Dictionary<FrameworkElement, TranslateTransform> active = [];
    static EntranceMotion() => MotionSettings.Changed += (_, _) =>
    {
        if (!MotionSettings.Enabled)
            foreach (var element in active.Keys.ToArray()) Stop(element);
    };
    public static void Play(FrameworkElement element, double milliseconds, double offset, double delay = 0)
    {
        Stop(element);
        if (!MotionSettings.Enabled) return;
        var shift = new TranslateTransform(); element.RenderTransform = shift;
        active[element] = shift; element.Unloaded += OnUnloaded;
        var duration = TimeSpan.FromMilliseconds(milliseconds);
        var opacity = new DoubleAnimation(0, 1, duration) { BeginTime = TimeSpan.FromMilliseconds(delay), FillBehavior = FillBehavior.Stop };
        opacity.Completed += (_, _) => Stop(element);
        shift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(offset, 0, duration)
        { BeginTime = TimeSpan.FromMilliseconds(delay), FillBehavior = FillBehavior.Stop, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
        element.BeginAnimation(UIElement.OpacityProperty, opacity);
    }
    private static void OnUnloaded(object sender, RoutedEventArgs e) => Stop((FrameworkElement)sender);
    private static void Stop(FrameworkElement element)
    {
        if (!active.Remove(element, out var shift)) return;
        element.BeginAnimation(UIElement.OpacityProperty, null); shift.BeginAnimation(TranslateTransform.YProperty, null);
        element.Unloaded -= OnUnloaded;
    }
}
