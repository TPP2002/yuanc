using System.Runtime.Versioning;
using Microsoft.Win32;
using WinClient.Core.Hosting;
using Xunit;

namespace WinClient.Tests;

[SupportedOSPlatform("windows")]
public sealed class EntryPointTests
{
    [Fact]
    public void ConstantsAndCommandAreExact()
    {
        using var sandbox = new Sandbox();
        var executable = sandbox.WriteExecutable("YuanC-Client.exe", 4096);
        Assert.Equal("澳洲出口客户端", EntryPoints.DisplayName);
        Assert.Equal("澳洲出口客户端.lnk", EntryPoints.ShortcutFileName);
        Assert.Equal("YuanC", EntryPoints.Publisher);
        Assert.Equal(@"Software\Microsoft\Windows\CurrentVersion\Uninstall", EntryPoints.UninstallParentPath);
        Assert.Equal("YuanC", EntryPoints.UninstallKeyName);
        Assert.Equal("--uninstall-prompt", EntryPoints.UninstallRole);
        Assert.Equal("开始菜单图标", EntryPoints.StartMenuItem);
        Assert.Equal("桌面图标", EntryPoints.DesktopItem);
        Assert.Equal("卸载入口", EntryPoints.UninstallItem);
        Assert.Equal("没有建成，重新安装一次可以补上。", EntryPoints.ApplyFailedSuffix);
        Assert.Equal("没有删掉，可以手动删除。", EntryPoints.RemoveFailedSuffix);
        Assert.Equal("确定卸载澳洲出口客户端吗？卸载会断开连接并撤掉断网保护，电脑恢复原来的网络。配对文件和日志会保留。",
            EntryPoints.UninstallConfirmText);
        Assert.Equal("已卸载。配对文件和日志还留在电脑上，重新安装后可以接着用。", EntryPoints.UninstallDoneText);
        Assert.Equal("卸载没有完成。请再试一次，或联系管理员。", EntryPoints.UninstallFailedText);
        Assert.Equal("\"" + Path.GetFullPath(executable) + "\" --uninstall-prompt", EntryPoints.UninstallCommand(executable));
        Assert.Null(EntryPoints.Describe([], EntryPoints.ApplyFailedSuffix));
        Assert.Equal("开始菜单图标、桌面图标没有建成，重新安装一次可以补上。",
            EntryPoints.Describe([EntryPoints.StartMenuItem, EntryPoints.DesktopItem], EntryPoints.ApplyFailedSuffix));
        Assert.Equal("卸载入口没有删掉，可以手动删除。",
            EntryPoints.Describe([EntryPoints.UninstallItem], EntryPoints.RemoveFailedSuffix));
    }

    [Fact]
    public void ShortcutRoundTripsThroughShellLink()
    {
        using var sandbox = new Sandbox();
        var executable = sandbox.WriteExecutable("YuanC-Client.exe", 4096);
        var linkPath = Path.Combine(sandbox.Root, EntryPoints.ShortcutFileName);
        ShellShortcut.Write(linkPath, new ShellShortcut.Link(Path.GetFullPath(executable), "--tray", sandbox.Root, EntryPoints.DisplayName));
        var read = ShellShortcut.Read(linkPath);
        Assert.NotNull(read);
        Assert.Equal(Path.GetFullPath(executable), read!.Target, ignoreCase: true);
        Assert.Equal("--tray", read.Arguments);
        Assert.Equal(sandbox.Root, read.WorkingDirectory, ignoreCase: true);
        Assert.Equal(EntryPoints.DisplayName, read.Description);
        Assert.Null(ShellShortcut.Read(Path.Combine(sandbox.Root, "missing.lnk")));
    }

    [Fact]
    public void ApplyCreatesShortcutsAndUninstallEntry()
    {
        using var sandbox = new Sandbox();
        using var hive = sandbox.NewHive();
        var executable = sandbox.WriteExecutable("YuanC-Client.exe", 4096);
        var points = new EntryPoints(Path.Combine(sandbox.Root, "programs"), Path.Combine(sandbox.Root, "desktop"), hive);
        Assert.Empty(points.Apply(executable, "1.2.3"));
        Assert.True(File.Exists(points.StartMenuShortcut));
        Assert.True(File.Exists(points.DesktopShortcut));
        foreach (var path in new[] { points.StartMenuShortcut, points.DesktopShortcut })
        {
            var read = ShellShortcut.Read(path);
            Assert.NotNull(read);
            Assert.Equal(Path.GetFullPath(executable), read!.Target, ignoreCase: true);
            Assert.Equal("", read.Arguments);
            Assert.Equal(Path.GetDirectoryName(Path.GetFullPath(executable))!, read.WorkingDirectory, ignoreCase: true);
            Assert.Equal(EntryPoints.DisplayName, read.Description);
        }
        using var key = hive.OpenSubKey(EntryPoints.UninstallParentPath + "\\" + EntryPoints.UninstallKeyName);
        Assert.NotNull(key);
        Assert.Equal(EntryPoints.DisplayName, key!.GetValue("DisplayName"));
        Assert.Equal("1.2.3", key.GetValue("DisplayVersion"));
        Assert.Equal(EntryPoints.Publisher, key.GetValue("Publisher"));
        Assert.Equal(Path.GetFullPath(executable), key.GetValue("DisplayIcon"));
        Assert.Equal(Path.GetDirectoryName(Path.GetFullPath(executable)), key.GetValue("InstallLocation"));
        Assert.Equal(EntryPoints.UninstallCommand(executable), key.GetValue("UninstallString"));
        Assert.Equal(1, (int)key.GetValue("NoModify")!);
        Assert.Equal(1, (int)key.GetValue("NoRepair")!);
        Assert.Equal(4, (int)key.GetValue("EstimatedSize")!);
        Assert.Equal(RegistryValueKind.String, key.GetValueKind("DisplayName"));
        Assert.Equal(RegistryValueKind.String, key.GetValueKind("UninstallString"));
        Assert.Equal(RegistryValueKind.DWord, key.GetValueKind("NoModify"));
        Assert.Equal(RegistryValueKind.DWord, key.GetValueKind("NoRepair"));
        Assert.Equal(RegistryValueKind.DWord, key.GetValueKind("EstimatedSize"));
    }

    [Fact]
    public void ApplyTwiceDoesNotRewriteAndFollowsNewExecutable()
    {
        using var sandbox = new Sandbox();
        using var hive = sandbox.NewHive();
        var executableA = sandbox.WriteExecutable("YuanC-Client.exe", 4096);
        var executableB = sandbox.WriteExecutable("YuanC-Client.exe", 4096, Path.Combine(sandbox.Root, "next"));
        var points = new EntryPoints(Path.Combine(sandbox.Root, "programs"), Path.Combine(sandbox.Root, "desktop"), hive);
        Assert.Empty(points.Apply(executableA, "1.0.0"));
        File.SetAttributes(points.StartMenuShortcut, FileAttributes.ReadOnly);
        File.SetAttributes(points.DesktopShortcut, FileAttributes.ReadOnly);
        Assert.Empty(points.Apply(executableA, "1.0.0"));
        File.SetAttributes(points.StartMenuShortcut, FileAttributes.Normal);
        File.SetAttributes(points.DesktopShortcut, FileAttributes.Normal);
        Assert.Empty(points.Apply(executableB, "2.0.0"));
        foreach (var path in new[] { points.StartMenuShortcut, points.DesktopShortcut })
        {
            var read = ShellShortcut.Read(path);
            Assert.NotNull(read);
            Assert.Equal(Path.GetFullPath(executableB), read!.Target, ignoreCase: true);
        }
        using var key = hive.OpenSubKey(EntryPoints.UninstallParentPath + "\\" + EntryPoints.UninstallKeyName);
        Assert.NotNull(key);
        Assert.Equal("2.0.0", key!.GetValue("DisplayVersion"));
        Assert.Equal(EntryPoints.UninstallCommand(executableB), key.GetValue("UninstallString"));
    }

    [Fact]
    public void RemoveDeletesAllAndToleratesMissing()
    {
        using var sandbox = new Sandbox();
        using var hive = sandbox.NewHive();
        var executable = sandbox.WriteExecutable("YuanC-Client.exe", 4096);
        var points = new EntryPoints(Path.Combine(sandbox.Root, "programs"), Path.Combine(sandbox.Root, "desktop"), hive);
        Assert.Empty(points.Apply(executable, "1.0.0"));
        Assert.Empty(points.Remove());
        Assert.False(File.Exists(points.StartMenuShortcut));
        Assert.False(File.Exists(points.DesktopShortcut));
        Assert.Null(hive.OpenSubKey(EntryPoints.UninstallParentPath + "\\" + EntryPoints.UninstallKeyName));
        Assert.Empty(points.Remove());
        using var fresh = sandbox.NewHive();
        var never = new EntryPoints(Path.Combine(sandbox.Root, "programs"), Path.Combine(sandbox.Root, "desktop"), fresh);
        Assert.Empty(never.Remove());
    }

    [Fact]
    public void ApplyReportsOnlyTheFailedItem()
    {
        using var sandbox = new Sandbox();
        using var hive = sandbox.NewHive();
        var executable = sandbox.WriteExecutable("YuanC-Client.exe", 4096);
        var blocker = Path.Combine(sandbox.Root, "blocker");
        File.WriteAllText(blocker, "block");
        var points = new EntryPoints(Path.Combine(blocker, "sub"), Path.Combine(sandbox.Root, "desktop"), hive);
        Assert.Equal(new[] { EntryPoints.StartMenuItem }, points.Apply(executable, "1.0.0"));
        Assert.True(File.Exists(points.DesktopShortcut));
        using var key = hive.OpenSubKey(EntryPoints.UninstallParentPath + "\\" + EntryPoints.UninstallKeyName);
        Assert.NotNull(key);
        Assert.Equal(EntryPoints.DisplayName, key!.GetValue("DisplayName"));
    }

    // 工作目录放在测试程序自己的目录下，注册表只用当前用户下的测试键，用完都删干净。
    private sealed class Sandbox : IDisposable
    {
        private readonly List<string> keys = [];
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory, "entry-points-tests", Guid.NewGuid().ToString("N"));
        public Sandbox() => Directory.CreateDirectory(Root);
        public string WriteExecutable(string name, int size, string? directory = null)
        {
            var path = Path.Combine(directory ?? Root, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, new byte[size]);
            return path;
        }
        public RegistryKey NewHive()
        {
            var path = @"Software\YuanC-Tests\" + Guid.NewGuid().ToString("N");
            keys.Add(path);
            return Registry.CurrentUser.CreateSubKey(path)!;
        }
        public void Dispose()
        {
            foreach (var path in keys) Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
            ForceDelete(Root);
        }
    }

    private static void ForceDelete(string root)
    {
        if (!Directory.Exists(root)) return;
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            try { File.SetAttributes(file, FileAttributes.Normal); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        Directory.Delete(root, recursive: true);
    }
}
