using System.Diagnostics;
using System.IO;
using System.Text;
using WinClient.Core.EnvironmentSupport;

namespace WinClient.App.Hosting;

internal static class VerifyPagePublisher
{
    public static string Directory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "YuanC", "verify");

    public static string WriteAndOpen(string html)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var path = Path.Combine(Directory, BrowserVerifyPage.FileName);
        var temp = path + ".tmp";
        File.WriteAllText(temp, html, new UTF8Encoding(false));
        File.Move(temp, path, overwrite: true);
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();
        return path;
    }
}
