using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using WinClient.App.Presentation;
using WinClient.App.Themes;
using Path = System.Windows.Shapes.Path;

namespace WinClient.App.Controls;

public partial class StatusTile : UserControl
{
    public static readonly DependencyProperty ToneProperty = DependencyProperty.Register(nameof(Tone), typeof(Tone), typeof(StatusTile), new PropertyMetadata(Tone.N, Changed));
    public static readonly DependencyProperty GlyphProperty = DependencyProperty.Register(nameof(Glyph), typeof(Glyph), typeof(StatusTile), new PropertyMetadata(Glyph.Ring, Changed));
    public static readonly DependencyProperty FlowProperty = DependencyProperty.Register(nameof(Flow), typeof(Flow), typeof(StatusTile), new PropertyMetadata(Flow.None, Changed));
    public static readonly DependencyProperty FilledProperty = DependencyProperty.Register(nameof(Filled), typeof(bool), typeof(StatusTile), new PropertyMetadata(false, Changed));
    public static readonly DependencyProperty DimProperty = DependencyProperty.Register(nameof(Dim), typeof(bool), typeof(StatusTile), new PropertyMetadata(false, Changed));
    public static readonly DependencyProperty TileSizeProperty = DependencyProperty.Register(nameof(TileSize), typeof(double), typeof(StatusTile), new PropertyMetadata(20d, Changed));
    public static readonly DependencyProperty SpecProperty = DependencyProperty.Register(nameof(Spec), typeof(TileSpec), typeof(StatusTile), new PropertyMetadata(null, SpecChanged));
    public Tone Tone { get => (Tone)GetValue(ToneProperty); set => SetValue(ToneProperty, value); }
    public Glyph Glyph { get => (Glyph)GetValue(GlyphProperty); set => SetValue(GlyphProperty, value); }
    public Flow Flow { get => (Flow)GetValue(FlowProperty); set => SetValue(FlowProperty, value); }
    public bool Filled { get => (bool)GetValue(FilledProperty); set => SetValue(FilledProperty, value); }
    public bool Dim { get => (bool)GetValue(DimProperty); set => SetValue(DimProperty, value); }
    public double TileSize { get => (double)GetValue(TileSizeProperty); set => SetValue(TileSizeProperty, value); }
    public TileSpec? Spec { get => (TileSpec?)GetValue(SpecProperty); set => SetValue(SpecProperty, value); }
    public bool IsFlowing => Flow != Flow.None && MotionSettings.Enabled;
    private readonly List<Action> stop = [];
    private bool applyingSpec;
    private bool pendingDraw;
    private int revision;

    public StatusTile()
    {
        InitializeComponent();
        Loaded += (_, _) => { MotionSettings.Changed += SettingsChanged; ThemeManager.ThemeChanged += SettingsChanged; Paint(false); };
        Unloaded += (_, _) => { MotionSettings.Changed -= SettingsChanged; ThemeManager.ThemeChanged -= SettingsChanged; StopClocks(); };
        Width = Height = TileSize;
    }
    private static void Changed(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var tile = (StatusTile)d;
        if (tile.applyingSpec) return;
        if (e.Property == FilledProperty && (bool)e.NewValue && !(bool)e.OldValue) tile.pendingDraw = true;
        tile.Width = tile.Height = tile.TileSize;
        if (tile.IsLoaded) tile.Paint(e.Property == ToneProperty);
    }
    private static void SpecChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var tile = (StatusTile)d;
        if (e.NewValue is not TileSpec spec) return;
        var oldTone = tile.Tone;
        tile.pendingDraw |= spec.Filled && !tile.Filled;
        tile.applyingSpec = true;
        tile.SetCurrentValue(ToneProperty, spec.Tone); tile.SetCurrentValue(GlyphProperty, spec.Glyph);
        tile.SetCurrentValue(FlowProperty, spec.Flow); tile.SetCurrentValue(FilledProperty, spec.Filled); tile.SetCurrentValue(DimProperty, spec.Dim);
        tile.applyingSpec = false;
        if (tile.IsLoaded) tile.Paint(oldTone != spec.Tone);
    }
    private void SettingsChanged(object? sender, EventArgs e)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.InvokeAsync(() => SettingsChanged(sender, e)); return; }
        Paint(false);
    }
    private void StopClocks()
    {
        revision++;
        foreach (var end in stop) end();
        stop.Clear();
    }
    private Duration Duration(string name) => (Duration)FindResource("Yc.Dur." + name);
    private void Animate(Animatable target, DependencyProperty property, AnimationTimeline animation)
    {
        if (!MotionSettings.Enabled) return;
        target.BeginAnimation(property, animation);
        stop.Add(() => target.BeginAnimation(property, null));
    }
    private void AnimateElement(UIElement target, DependencyProperty property, AnimationTimeline animation)
    {
        if (!MotionSettings.Enabled) return;
        target.BeginAnimation(property, animation);
        stop.Add(() => target.BeginAnimation(property, null));
    }
    private static DoubleAnimation Loop(double from, double to, double seconds, double delay = 0) => new(from, to, TimeSpan.FromSeconds(seconds / 2))
    { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever, BeginTime = TimeSpan.FromSeconds(delay) };

    private void Paint(bool toneChanged)
    {
        var oldColor = (Inner.Background as SolidColorBrush)?.Color;
        StopClocks();
        Width = Height = TileSize;
        Opacity = Dim ? .5 : 1;
        var large = TileSize == 56;
        Outer.CornerRadius = new(large ? 14 : 6); Outer.Padding = new(large ? 3 : 1.5);
        Inner.CornerRadius = new(large ? 11 : 4.5); MarkBox.Width = MarkBox.Height = large ? 34 : 14;
        var toneKey = "Yc." + Tone;
        var backgroundKey = toneKey + (Filled ? "" : "Bg");
        Inner.SetResourceReference(Border.BackgroundProperty, backgroundKey);
        Outer.SetResourceReference(Border.BackgroundProperty, Flow == Flow.None ? "Yc.Line" : toneKey);
        if (IsFlowing)
        {
            var brush = ((LinearGradientBrush)FindResource("Yc.Spec." + Tone)).CloneCurrentValue();
            var shift = new TranslateTransform(); brush.RelativeTransform = shift; Outer.Background = brush;
            Animate(shift, TranslateTransform.XProperty, new DoubleAnimation(0, Flow == Flow.Reverse ? -1 : 1,
                Duration(Flow == Flow.Fast ? "FlowFast" : "Flow")) { RepeatBehavior = RepeatBehavior.Forever });
        }
        if (toneChanged && MotionSettings.Enabled && oldColor is Color from)
        {
            var to = ((SolidColorBrush)FindResource(backgroundKey)).Color;
            var brush = new SolidColorBrush(to); Inner.Background = brush;
            var animation = new ColorAnimation(from, to, Duration("Small")) { FillBehavior = FillBehavior.Stop };
            var current = revision;
            animation.Completed += (_, _) => { if (revision == current) Inner.SetResourceReference(Border.BackgroundProperty, backgroundKey); };
            Animate(brush, SolidColorBrush.ColorProperty, animation);
        }
        Mark.Children.Clear();
        var geometry = (Geometry)FindResource("Yc.Glyph." + Glyph);
        if (Glyph is Glyph.Bars or Glyph.Dots or Glyph.Ask or Glyph.Bang && geometry is GeometryGroup)
        {
            var group = (GeometryGroup)geometry;
            for (var i = 0; i < group.Children.Count; i++)
            {
                var path = MakePath(group.Children[i], large);
                Mark.Children.Add(path);
                if (Glyph == Glyph.Bars)
                {
                    if (i == 0) path.Opacity = .45;
                    else if (IsFlowing)
                    {
                        var transform = new ScaleTransform(1, 1); path.RenderTransform = transform;
                        path.RenderTransformOrigin = new(.5, 1);
                        Animate(transform, ScaleTransform.ScaleYProperty, Loop(.25, 1, 2.4, (i - 1) * .25));
                    }
                }
                else if (Glyph == Glyph.Dots)
                {
                    path.Stroke = null; path.SetResourceReference(Shape.FillProperty, Filled ? "Yc.Bg" : toneKey);
                    if (IsFlowing)
                    {
                        var transform = new TranslateTransform(); path.RenderTransform = transform;
                        Animate(transform, TranslateTransform.YProperty, Loop(0, -1.6, 1.6, i * .2));
                        AnimateElement(path, OpacityProperty, Loop(.3, 1, 1.6, i * .2));
                    }
                }
                else if (i == 1) path.StrokeThickness = 2.8;
            }
        }
        else
        {
            var path = MakePath(geometry, large); Mark.Children.Add(path);
            if (Glyph == Glyph.Ring) path.StrokeDashArray = new([2.3 / path.StrokeThickness, 2.3 / path.StrokeThickness]);
            if (Glyph == Glyph.Check && Filled && pendingDraw && MotionSettings.Enabled)
            {
                path.StrokeDashArray = new([26d, 26d]);
                AnimateElement(path, Shape.StrokeDashOffsetProperty, new DoubleAnimation(26, 0, Duration("Draw"))
                { FillBehavior = FillBehavior.Stop, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
            }
        }
        Mark.RenderTransform = Transform.Identity; Mark.Opacity = 1;
        if (IsFlowing && Glyph == Glyph.Spin)
        {
            var rotation = new RotateTransform(0, 12, 12); Mark.RenderTransform = rotation;
            Animate(rotation, RotateTransform.AngleProperty, new DoubleAnimation(0, -360, TimeSpan.FromSeconds(3.2)) { RepeatBehavior = RepeatBehavior.Forever });
        }
        if (IsFlowing && Glyph == Glyph.Ask)
        {
            var scale = new ScaleTransform(1, 1, 12, 12); Mark.RenderTransform = scale;
            Animate(scale, ScaleTransform.ScaleXProperty, Loop(1, .9, 2.4)); Animate(scale, ScaleTransform.ScaleYProperty, Loop(1, .9, 2.4));
            AnimateElement(Mark, OpacityProperty, Loop(1, .45, 2.4));
        }
        pendingDraw = false;
    }
    private Path MakePath(Geometry geometry, bool large)
    {
        var path = new Path { Data = geometry, StrokeThickness = large ? 2 : 2.2, StrokeStartLineCap = PenLineCap.Round,
            StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round };
        path.SetResourceReference(Shape.StrokeProperty, Filled ? "Yc.Bg" : "Yc." + Tone);
        return path;
    }
}
