using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using WinClient.App.Presentation;

namespace WinClient.App.Themes;

public sealed class PageChoiceConverter : IValueConverter
{
    public static PageChoiceConverter Instance { get; } = new();
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => Equals(value, parameter);
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is true ? parameter : Binding.DoNothing;
}

public sealed class VisibilityConverter : IValueConverter
{
    public static VisibilityConverter Instance { get; } = new();
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var visible = value switch { bool b => b, string s => s.Length > 0, int n => n > 0, _ => value is not null };
        if (parameter is "Invert") visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class SemanticText : DependencyObject
{
    public static readonly DependencyProperty ToneProperty = DependencyProperty.RegisterAttached("Tone", typeof(Tone), typeof(SemanticText), new PropertyMetadata(Tone.N, Apply));
    public static readonly DependencyProperty NormalKeyProperty = DependencyProperty.RegisterAttached("NormalKey", typeof(string), typeof(SemanticText), new PropertyMetadata("Yc.Text", Apply));
    public static Tone GetTone(DependencyObject d) => (Tone)d.GetValue(ToneProperty);
    public static void SetTone(DependencyObject d, Tone value) => d.SetValue(ToneProperty, value);
    public static string GetNormalKey(DependencyObject d) => (string)d.GetValue(NormalKeyProperty);
    public static void SetNormalKey(DependencyObject d, string value) => d.SetValue(NormalKeyProperty, value);
    private static void Apply(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is TextBlock text) text.SetResourceReference(TextBlock.ForegroundProperty,
            GetTone(d) == Tone.N ? GetNormalKey(d) : "Yc." + GetTone(d));
    }
}
