using System.Security;
using System.Windows;
using Microsoft.Win32;

namespace WinClient.App.Themes;

public enum ThemeKind { Light, Dark }

public static class ThemeManager
{
    private static bool started;
    public static ThemeKind Current { get; private set; }
    public static event EventHandler? ThemeChanged;

    public static ThemeKind Detect()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", writable: false);
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0 ? ThemeKind.Dark : ThemeKind.Light;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or System.IO.IOException)
        { return ThemeKind.Light; }
    }

    public static void Apply(ResourceDictionary target, ThemeKind kind)
    {
        var replacement = new ResourceDictionary { Source = new Uri($"/WinClient.App;component/Themes/Tokens.{kind}.xaml", UriKind.Relative) };
        for (var i = target.MergedDictionaries.Count - 1; i >= 0; i--)
        {
            var source = target.MergedDictionaries[i].Source?.OriginalString;
            if (source is not null && (source.EndsWith("/Tokens.Light.xaml", StringComparison.Ordinal) || source.EndsWith("/Tokens.Dark.xaml", StringComparison.Ordinal)))
                target.MergedDictionaries.RemoveAt(i);
        }
        target.MergedDictionaries.Add(replacement);
        Current = kind;
    }

    public static void Start()
    {
        if (started) return;
        SystemEvents.UserPreferenceChanged += OnPreferenceChanged;
        started = true;
    }

    public static void Stop()
    {
        if (!started) return;
        SystemEvents.UserPreferenceChanged -= OnPreferenceChanged;
        started = false;
    }

    private static void OnPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        var application = Application.Current;
        var dispatcher = application?.Dispatcher;
        if (dispatcher is null || dispatcher.HasShutdownStarted) return;
        dispatcher.InvokeAsync(() =>
        {
            Apply(application!.Resources, Detect());
            MotionSettings.Refresh();
            ThemeChanged?.Invoke(null, EventArgs.Empty);
        });
    }
}
