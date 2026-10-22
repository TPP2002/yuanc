using System.Windows;

namespace WinClient.App.Themes;

public static class MotionSettings
{
    private static bool? motionOverride;
    public static bool Enabled => Override ?? SystemParameters.ClientAreaAnimation;
    public static bool? Override
    {
        get => motionOverride;
        set { if (motionOverride == value) return; motionOverride = value; Refresh(); }
    }
    public static event EventHandler? Changed;
    public static void Refresh()
    {
        _ = Enabled;
        Changed?.Invoke(null, EventArgs.Empty);
    }
}
