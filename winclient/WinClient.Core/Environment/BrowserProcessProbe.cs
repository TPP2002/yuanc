using System.ComponentModel;
using System.Diagnostics;

namespace WinClient.Core.EnvironmentSupport;

public interface IBrowserProcessProbe
{
    IReadOnlyList<string>? RunningBrowsers();
}

public sealed class SystemBrowserProcessProbe : IBrowserProcessProbe
{
    internal static readonly (string Process, string Display)[] Browsers = [("chrome", "Chrome"), ("msedge", "Edge")];

    public IReadOnlyList<string>? RunningBrowsers()
    {
        try
        {
            var running = new List<string>();
            foreach (var (name, display) in Browsers)
            {
                var processes = System.Diagnostics.Process.GetProcessesByName(name);
                try
                {
                    if (processes.Length > 0) running.Add(display);
                }
                finally
                {
                    foreach (var process in processes) process.Dispose();
                }
            }
            return running;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or PlatformNotSupportedException)
        {
            return null;
        }
    }
}
