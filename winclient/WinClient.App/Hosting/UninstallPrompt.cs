using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.Update;

namespace WinClient.App.Hosting;

/// <summary>从系统「应用和功能」点卸载时走这里：先确认，再卸载，最后关掉还开着的界面并给出结果。</summary>
public static class UninstallPrompt
{
    public static int Run()
    {
        var answer = System.Windows.MessageBox.Show(EntryPoints.UninstallConfirmText, EntryPoints.DisplayName,
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return 0;
        bool done;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            done = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
                ? new InstallerRunner().RunAsync("--uninstall").GetAwaiter().GetResult() == 0
                : InstallerRunner.ElevateAsync("--uninstall").GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            done = false;
        }
        if (done)
        {
            CloseRunningUi();
            MessageBox.Show(EntryPoints.UninstallDoneText, EntryPoints.DisplayName);
            return 0;
        }
        MessageBox.Show(EntryPoints.UninstallFailedText, EntryPoints.DisplayName);
        return 1;
    }

    // 只关安装目录里的本产品界面；安装目录之外的同名程序一律不动。
    private static void CloseRunningUi()
    {
        var name = Path.GetFileNameWithoutExtension(InstallerRunner.CurrentExecutable);
        foreach (var process in Process.GetProcessesByName(name))
        {
            try
            {
                if (process.Id == Environment.ProcessId) continue;
                if (process.MainModule?.FileName is { } image && CallerIdentity.IsTrusted(image, UpdatePlanner.DefaultAppRoot))
                    process.Kill();
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException) { }
            finally
            {
                process.Dispose();
            }
        }
    }
}
