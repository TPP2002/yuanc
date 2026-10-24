using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;

namespace WinClient.App.Themes;

public static class MonoText
{
    public static readonly DependencyProperty TextProperty = DependencyProperty.RegisterAttached("Text", typeof(string), typeof(MonoText), new PropertyMetadata(null, OnTextChanged));
    internal static readonly Regex Token = new(@"(?<![0-9A-Za-z.:])(?:\d+(?:\.\d+)+|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])", RegexOptions.CultureInvariant);

    public static string? GetText(DependencyObject d) => (string?)d.GetValue(TextProperty);
    public static void SetText(DependencyObject d, string? value) => d.SetValue(TextProperty, value);

    public static IReadOnlyList<(string Text, bool Mono)> Split(string? text)
    {
        if (string.IsNullOrEmpty(text)) return [];
        var parts = new List<(string Text, bool Mono)>();
        var position = 0;
        foreach (Match match in Token.Matches(text))
        {
            if (match.Index > position) parts.Add((text[position..match.Index], false));
            parts.Add((match.Value, true));
            position = match.Index + match.Length;
        }
        if (position < text.Length) parts.Add((text[position..], false));
        return parts;
    }

    private static void OnTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextBlock text) return;
        text.Inlines.Clear();
        foreach (var part in Split((string?)e.NewValue))
        {
            var run = new Run(part.Text);
            if (part.Mono) run.SetResourceReference(TextElement.FontFamilyProperty, "Yc.Font.Mono");
            text.Inlines.Add(run);
        }
    }
}
