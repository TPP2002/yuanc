using System.Runtime.Versioning;
using System.Security;
using Microsoft.Win32;

namespace WinClient.Core.Hosting;

/// <summary>开始菜单图标、桌面图标，以及系统「应用和功能」里的卸载入口。</summary>
[SupportedOSPlatform("windows")]
public sealed class EntryPoints(string programsDirectory, string desktopDirectory, RegistryKey hive)
{
    public const string DisplayName = "澳洲出口客户端";
    public const string ShortcutFileName = "澳洲出口客户端.lnk";
    public const string Publisher = "YuanC";
    public const string UninstallParentPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    public const string UninstallKeyName = "YuanC";
    public const string UninstallRole = "--uninstall-prompt";
    public const string StartMenuItem = "开始菜单图标";
    public const string DesktopItem = "桌面图标";
    public const string UninstallItem = "卸载入口";
    public const string ApplyFailedSuffix = "没有建成，重新安装一次可以补上。";
    public const string RemoveFailedSuffix = "没有删掉，可以手动删除。";
    public const string UninstallConfirmText = "确定卸载澳洲出口客户端吗？卸载会断开连接并撤掉断网保护，电脑恢复原来的网络。配对文件和日志会保留。";
    public const string UninstallDoneText = "已卸载。配对文件和日志还留在电脑上，重新安装后可以接着用。";
    public const string UninstallFailedText = "卸载没有完成。请再试一次，或联系管理员。";

    public string StartMenuShortcut { get; } = Path.Combine(Path.GetFullPath(programsDirectory), ShortcutFileName);
    public string DesktopShortcut { get; } = Path.Combine(Path.GetFullPath(desktopDirectory), ShortcutFileName);

    public static string UninstallCommand(string executable) => $"\"{Path.GetFullPath(executable)}\" {UninstallRole}";

    public static EntryPoints ForMachine() => new(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
        Registry.LocalMachine);

    public static string? Describe(IReadOnlyList<string> failed, string suffix) =>
        failed.Count == 0 ? null : string.Join("、", failed) + suffix;

    public IReadOnlyList<string> Apply(string executable, string version)
    {
        var failed = new List<string>();
        var target = Path.GetFullPath(executable);
        var directory = Path.GetDirectoryName(target)!;
        var link = new ShellShortcut.Link(target, "", directory, DisplayName);
        try { ApplyShortcut(StartMenuShortcut, link); }
        catch (Exception ex) when (Handled(ex)) { failed.Add(StartMenuItem); }
        try { ApplyShortcut(DesktopShortcut, link); }
        catch (Exception ex) when (Handled(ex)) { failed.Add(DesktopItem); }
        try { ApplyUninstallEntry(target, directory, version); }
        catch (Exception ex) when (Handled(ex)) { failed.Add(UninstallItem); }
        return failed;
    }

    public IReadOnlyList<string> Remove()
    {
        var failed = new List<string>();
        try { DeleteShortcut(StartMenuShortcut); }
        catch (Exception ex) when (Handled(ex)) { failed.Add(StartMenuItem); }
        try { DeleteShortcut(DesktopShortcut); }
        catch (Exception ex) when (Handled(ex)) { failed.Add(DesktopItem); }
        try { RemoveUninstallEntry(); }
        catch (Exception ex) when (Handled(ex)) { failed.Add(UninstallItem); }
        return failed;
    }

    // 内容和要写的一样就不动；不一样、读不到或读的时候出错，才重写一份。
    private static void ApplyShortcut(string path, ShellShortcut.Link link)
    {
        try
        {
            var existing = ShellShortcut.Read(path);
            if (existing is not null
                && string.Equals(existing.Target, link.Target, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.Arguments, link.Arguments, StringComparison.Ordinal)
                && string.Equals(existing.WorkingDirectory, link.WorkingDirectory, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.Description, link.Description, StringComparison.Ordinal))
                return;
        }
        catch (Exception) { /* 读不出来就当没有，下面重写一份。 */ }
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        ShellShortcut.Write(path, link);
    }

    private void ApplyUninstallEntry(string target, string directory, string version)
    {
        using var key = hive.CreateSubKey(UninstallParentPath + "\\" + UninstallKeyName, writable: true)
            ?? throw new IOException("无法创建卸载登记项。");
        var strings = new (string Name, string Value)[]
        {
            ("DisplayName", DisplayName),
            ("DisplayVersion", version),
            ("Publisher", Publisher),
            ("DisplayIcon", target),
            ("InstallLocation", directory),
            ("UninstallString", UninstallCommand(target)),
        };
        foreach (var (name, value) in strings)
        {
            if (key.GetValue(name) is string existing && string.Equals(existing, value, StringComparison.Ordinal)) continue;
            key.SetValue(name, value, RegistryValueKind.String);
        }
        var size = File.Exists(target) ? (int)(new FileInfo(target).Length / 1024) : 0;
        var numbers = new (string Name, int Value)[] { ("NoModify", 1), ("NoRepair", 1), ("EstimatedSize", size) };
        foreach (var (name, value) in numbers)
        {
            if (key.GetValue(name) is int existing && existing == value) continue;
            key.SetValue(name, value, RegistryValueKind.DWord);
        }
    }

    private static void DeleteShortcut(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }

    private void RemoveUninstallEntry()
    {
        using var parent = hive.OpenSubKey(UninstallParentPath, writable: true);
        parent?.DeleteSubKeyTree(UninstallKeyName, throwOnMissingSubKey: false);
    }

    private static bool Handled(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or SecurityException
            or System.Runtime.InteropServices.COMException or ArgumentException or NotSupportedException or InvalidCastException;
}
