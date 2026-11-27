using WinClient.Core.Hosting;
using Xunit;

namespace WinClient.Tests;

public sealed class UiHandoverTests
{
    private static string AppRoot => Path.GetFullPath("Program Files/YuanC/app");
    private static string Installed(string version) => Path.Combine(AppRoot, version, "YuanC-Client.exe");
    private static string Downloaded => Path.GetFullPath("Users/Someone/Downloads/YuanC-Client.exe");

    // 走到这里说明判定顺序错了：Stay 与 Reinstall 的前置分支都不该读文件。
    private static Func<string, bool> NoExists => _ => throw new Xunit.Sdk.XunitException("不应读取程序是否存在");
    private static Func<string, string, bool> NoHash => (_, _) => throw new Xunit.Sdk.XunitException("不应比较文件内容");

    [Fact]
    public void ServiceExecutableReadsQuotedPathFromServiceCommand()
    {
        var exe = Installed("0.1.0");
        var command = ServiceInstaller.ServiceCommand(exe);
        Assert.Equal(exe, UiHandover.ServiceExecutable(command));
        Assert.Equal(exe, UiHandover.ServiceExecutable("  " + command + "  "));
    }

    [Fact]
    public void ServiceExecutableRejectsOtherShapes()
    {
        var exe = Installed("0.1.0");
        var quoted = "\"" + exe + "\"";
        var relative = "\"Program Files\\YuanC\\app\\0.1.0\\YuanC-Client.exe\" --service";
        Assert.Null(UiHandover.ServiceExecutable(null));
        Assert.Null(UiHandover.ServiceExecutable(""));
        Assert.Null(UiHandover.ServiceExecutable("   "));
        Assert.Null(UiHandover.ServiceExecutable(exe + " --service"));
        Assert.Null(UiHandover.ServiceExecutable(quoted + " --tray"));
        Assert.Null(UiHandover.ServiceExecutable(quoted));
        Assert.Null(UiHandover.ServiceExecutable(quoted + " --service extra"));
        Assert.Null(UiHandover.ServiceExecutable(relative));
    }

    [Fact]
    public void StaysWhenAlreadyUnderAppRoot()
    {
        var decision = UiHandover.Decide(Installed("0.1.0"), "0.1.0", AppRoot, Installed("0.1.0"), NoExists, NoHash);
        Assert.Equal(UiHandoverKind.Stay, decision.Kind);
        Assert.Null(decision.Target);
        Assert.Null(decision.InstalledVersion);
    }

    [Fact]
    public void HandsOverToIdenticalInstalledCopy()
    {
        var service = Installed("0.1.0");
        var decision = UiHandover.Decide(Downloaded, "0.1.1", AppRoot, service, _ => true, (_, _) => true);
        Assert.Equal(UiHandoverKind.Handover, decision.Kind);
        Assert.Equal(Path.GetFullPath(service), decision.Target);
        Assert.Null(decision.InstalledVersion);
    }

    [Fact]
    public void OffersUpgradeWhenThisFileIsNewerThanInstalled()
    {
        var service = Installed("0.1.0");
        var decision = UiHandover.Decide(Downloaded, "0.1.1", AppRoot, service, _ => true, (_, _) => false);
        Assert.Equal(UiHandoverKind.Upgrade, decision.Kind);
        Assert.Equal(Path.GetFullPath(service), decision.Target);
        Assert.Equal("0.1.0", decision.InstalledVersion);
        var prerelease = UiHandover.Decide(Downloaded, "0.2.0-rc1", AppRoot, Installed("0.1.9"), _ => true, (_, _) => false);
        Assert.Equal(UiHandoverKind.Upgrade, prerelease.Kind);
        Assert.Equal("0.1.9", prerelease.InstalledVersion);
    }

    [Fact]
    public void HandsOverWhenInstalledIsSameOrNewerOrUnparsable()
    {
        foreach (var (currentVersion, installedVersion) in new[]
        {
            ("0.1.0", "0.1.0"), ("0.1.0", "0.2.0"), ("0.1.1-rc1", "0.1.1"), ("0.1.1", "weird"), ("", "0.1.0")
        })
        {
            var decision = UiHandover.Decide(Downloaded, currentVersion, AppRoot, Installed(installedVersion), _ => true, (_, _) => false);
            Assert.Equal(UiHandoverKind.Handover, decision.Kind);
            Assert.Null(decision.InstalledVersion);
        }
    }

    [Fact]
    public void ReinstallWhenInstalledCopyIsUnusable()
    {
        var evil = Path.GetFullPath("Program Files/Evil/YuanC-Client.exe");
        var separator = Path.DirectorySeparatorChar;
        var escaping = AppRoot + separator + "0.1.0" + separator + ".." + separator + ".." + separator + "Evil" + separator + "YuanC-Client.exe";
        foreach (var service in new string?[] { null, "", evil, escaping, AppRoot })
        {
            var decision = UiHandover.Decide(Downloaded, "0.1.1", AppRoot, service, NoExists, NoHash);
            Assert.Equal(UiHandoverKind.Reinstall, decision.Kind);
            Assert.Null(decision.Target);
        }
        var missing = UiHandover.Decide(Downloaded, "0.1.1", AppRoot, Installed("0.1.0"), _ => false, NoHash);
        Assert.Equal(UiHandoverKind.Reinstall, missing.Kind);
        Assert.Null(missing.Target);
    }

    [Fact]
    public void SameContentNeedsEqualLengthAndHash()
    {
        var directory = Path.Combine(Path.GetTempPath(), "yc-ui-handover-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var first = Path.Combine(directory, "first.exe");
            var identical = Path.Combine(directory, "identical.exe");
            var sameLength = Path.Combine(directory, "same-length.exe");
            var shorter = Path.Combine(directory, "shorter.exe");
            File.WriteAllText(first, "same-content");
            File.WriteAllText(identical, "same-content");
            File.WriteAllText(sameLength, "diff-content");
            File.WriteAllText(shorter, "short");
            Assert.True(UiHandover.SameContent(first, identical));
            Assert.False(UiHandover.SameContent(first, sameLength));
            Assert.False(UiHandover.SameContent(first, shorter));
            Assert.False(UiHandover.SameContent(first, Path.Combine(directory, "missing.exe")));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void SwitchesExecutableOnlyWhenRegisteredPathDiffers()
    {
        var first = Installed("0.1.0");
        Assert.False(ServiceInstaller.SwitchesExecutable(null, first));
        Assert.False(ServiceInstaller.SwitchesExecutable("   ", first));
        Assert.False(ServiceInstaller.SwitchesExecutable(first.ToUpperInvariant(), first));
        Assert.True(ServiceInstaller.SwitchesExecutable(Installed("0.0.9"), first));
    }
}
