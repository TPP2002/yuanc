using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace WinClient.App.Themes;

/// <summary>控件反馈只改变变换或颜色；系统关闭动画时立即撤掉时钟。</summary>
public sealed class ControlMotion : DependencyObject
{
    public static readonly DependencyProperty KindProperty = DependencyProperty.RegisterAttached("Kind", typeof(string), typeof(ControlMotion), new PropertyMetadata("", Attach));
    public static string GetKind(DependencyObject value) => (string)value.GetValue(KindProperty);
    public static void SetKind(DependencyObject value, string kind) => value.SetValue(KindProperty, kind);
    public static readonly DependencyProperty IsBusyProperty = DependencyProperty.RegisterAttached("IsBusy", typeof(bool), typeof(ControlMotion), new PropertyMetadata(false));
    public static bool GetIsBusy(DependencyObject value) => (bool)value.GetValue(IsBusyProperty);
    public static void SetIsBusy(DependencyObject value, bool busy) => value.SetValue(IsBusyProperty, busy);

    private static void Attach(DependencyObject value, DependencyPropertyChangedEventArgs e)
    {
        if (value is not Control control || e.OldValue is not "") return;
        var feedback = new Feedback(control);
        control.Loaded += feedback.Loaded;
        control.Unloaded += feedback.Unloaded;
    }

    private sealed class Feedback(Control control)
    {
        private bool active;
        private ScaleTransform? scale;
        private TranslateTransform? slider;
        private SolidColorBrush? face;
        private Border? animatedFace;
        private Color? previousColor;
        public void Loaded(object sender, RoutedEventArgs e)
        {
            if (active) return;
            active = true;
            MotionSettings.Changed += Reset;
            ThemeManager.ThemeChanged += Reset;
            previousColor = (control.Background as SolidColorBrush)?.Color;
            if (GetKind(control) == "Switch")
            {
                if (control.Template.FindName("Thumb", control) is Ellipse thumb)
                {
                    slider = new TranslateTransform();
                    thumb.RenderTransform = slider;
                }
                ((ToggleButton)control).Checked += Toggle; ((ToggleButton)control).Unchecked += Toggle;
                Slide(false);
            }
            else
            {
                if (GetKind(control) == "Button")
                {
                    scale = new ScaleTransform(1, 1); control.RenderTransform = scale; control.RenderTransformOrigin = new(.5, .5);
                    control.PreviewMouseDown += Press; control.PreviewMouseUp += Release;
                    control.PreviewKeyDown += KeyDown; control.PreviewKeyUp += KeyUp; control.LostMouseCapture += Release;
                }
                control.MouseEnter += Hover; control.MouseLeave += Hover;
                if (control is RadioButton radio) { radio.Checked += Toggle; radio.Unchecked += Toggle; }
            }
        }
        public void Unloaded(object sender, RoutedEventArgs e)
        {
            if (!active) return;
            active = false; MotionSettings.Changed -= Reset; ThemeManager.ThemeChanged -= Reset; Reset(null, EventArgs.Empty);
            control.MouseEnter -= Hover; control.MouseLeave -= Hover;
            control.PreviewMouseDown -= Press; control.PreviewMouseUp -= Release;
            control.PreviewKeyDown -= KeyDown; control.PreviewKeyUp -= KeyUp; control.LostMouseCapture -= Release;
            if (control is ToggleButton toggle) { toggle.Checked -= Toggle; toggle.Unchecked -= Toggle; }
        }
        private void Reset(object? sender, EventArgs e)
        {
            scale?.BeginAnimation(ScaleTransform.ScaleXProperty, null); scale?.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            face?.BeginAnimation(SolidColorBrush.ColorProperty, null);
            animatedFace?.ClearValue(Border.BackgroundProperty);
            previousColor = (control.Background as SolidColorBrush)?.Color;
            Slide(false);
        }
        private void Press(object sender, MouseButtonEventArgs e) { Scale(.97); FadeFace(); }
        private void Release(object sender, MouseEventArgs e) { Scale(1); FadeFace(); }
        private void KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Space) { Scale(.97); FadeFace(); } }
        private void KeyUp(object sender, KeyEventArgs e) { if (e.Key == Key.Space) { Scale(1); FadeFace(); } }
        private void Scale(double to)
        {
            if (scale is null || !MotionSettings.Enabled || !control.IsEnabled) return;
            var duration = (Duration)control.FindResource("Yc.Dur.Press");
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(to, duration));
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(to, duration));
        }
        private void Toggle(object sender, RoutedEventArgs e) { if (GetKind(control) == "Switch") Slide(true); else FadeFace(); }
        private void Hover(object sender, MouseEventArgs e) => FadeFace();
        private void FadeFace()
        {
            control.Dispatcher.InvokeAsync(() =>
            {
                if (!active || control.Background is not SolidColorBrush background) return;
                var to = background.Color;
                var from = face?.HasAnimatedProperties == true ? face.Color : previousColor ?? to;
                previousColor = to;
                if (!MotionSettings.Enabled) return;
                var border = VisualTreeHelper.GetChildrenCount(control) > 0 ? VisualTreeHelper.GetChild(control, 0) as Border : null;
                if (border is null) return;
                face?.BeginAnimation(SolidColorBrush.ColorProperty, null);
                var brush = new SolidColorBrush(to); face = brush; animatedFace = border; border.Background = brush;
                var animation = new ColorAnimation(from, to, (Duration)control.FindResource("Yc.Dur.Press")) { FillBehavior = FillBehavior.Stop };
                animation.Completed += (_, _) => { if (ReferenceEquals(face, brush)) border.ClearValue(Border.BackgroundProperty); };
                brush.BeginAnimation(SolidColorBrush.ColorProperty, animation);
            }, System.Windows.Threading.DispatcherPriority.Render);
        }
        private void Slide(bool animate)
        {
            if (slider is null) return;
            var from = slider.X; var to = ((ToggleButton)control).IsChecked == true ? 18d : 0d;
            slider.BeginAnimation(TranslateTransform.XProperty, null); slider.X = to;
            if (animate && MotionSettings.Enabled)
                slider.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(from, to, (Duration)control.FindResource("Yc.Dur.Small")) { FillBehavior = FillBehavior.Stop });
        }
    }
}
