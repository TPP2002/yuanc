using System.Xml.Linq;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using Xunit;

namespace WinClient.Tests;

public sealed class HostingTests
{
    [Theory]
    [InlineData(false, "create")]
    [InlineData(true, "config")]
    public void ServiceArgumentsAreExact(bool exists, string verb)
    {
        var exe = Path.GetFullPath("Program Files/YuanC/app/0.1.0/YuanC-Client.exe");
        Assert.Equal(new[] { verb, "YuanCService", "binPath=", $"\"{exe}\" --service", "start=", "auto", "depend=", "BFE", "DisplayName=", "YuanC 澳洲出口连接服务", "obj=", "LocalSystem" }, ServiceInstaller.Configure(exe, exists));
        Assert.Equal(new[] { "description", "YuanCService", "保持澳洲出口隧道与断网保护在后台运行" }, ServiceInstaller.Describe());
        Assert.Equal(new[] { "failure", "YuanCService", "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000" }, ServiceInstaller.FailureActions());
        Assert.Equal(new[] { "failureflag", "YuanCService", "1" }, ServiceInstaller.FailureFlag());
        Assert.Equal(new[] { "start", "YuanCService" }, ServiceInstaller.Start());
        Assert.Equal(new[] { "stop", "YuanCService" }, ServiceInstaller.Stop());
        Assert.Equal(new[] { "delete", "YuanCService" }, ServiceInstaller.Delete());
        Assert.Equal($"\"{exe}\" --tray", ServiceInstaller.RunValue(exe));
        Assert.Equal(@"Software\Microsoft\Windows\CurrentVersion\Run", ServiceInstaller.RunKey);
        Assert.Equal("YuanC", ServiceInstaller.RunValueName);
    }

    [Fact]
    public void VersionedInstallationAndCopyDecisionAreIdempotent()
    {
        var root = Path.GetFullPath("Program Files");
        Assert.Equal(Path.Combine(root, "YuanC", "app", "0.1.0", "YuanC-Client.exe"), ServiceInstaller.InstalledExecutable(root, "0.1.0+commit"));
        Assert.False(ServiceInstaller.ShouldCopy("AABB", "aabb"));
        Assert.True(ServiceInstaller.ShouldCopy("AABB", null));
        Assert.True(ServiceInstaller.ShouldCopy("AABB", "AABC"));
        Assert.Throws<ArgumentException>(() => ServiceInstaller.ReleaseVersion("../outside"));
    }

    [Fact]
    public void AllSystemCommandsAreHiddenAndUseFullPathsAndArgumentLists()
    {
        var root = Path.GetFullPath("Windows/System32");
        var exe = Path.GetFullPath("Program Files/YuanC/YuanC-Client.exe");
        var commands = new[] { ServiceInstaller.Configure(exe, false), ServiceInstaller.Configure(exe, true), ServiceInstaller.Describe(), ServiceInstaller.FailureActions(), ServiceInstaller.FailureFlag(), ServiceInstaller.Start(), ServiceInstaller.Stop(), ServiceInstaller.Delete() };
        foreach (var command in commands)
        {
            var info = ServiceInstaller.CreateStartInfo(root, command);
            Assert.Equal(Path.Combine(root, "sc.exe"), info.FileName);
            Assert.Equal(root, info.WorkingDirectory);
            Assert.True(info.CreateNoWindow); Assert.False(info.UseShellExecute);
            Assert.True(info.RedirectStandardOutput); Assert.True(info.RedirectStandardError);
            Assert.Equal(command, info.ArgumentList);
        }
    }

    [Fact]
    public void ConnectionBudgetLimitsPerClientAndTotal()
    {
        var budget = new ConnectionBudget(4, 2);
        Assert.True(budget.TryAdmit(10)); Assert.True(budget.TryAdmit(10));
        Assert.False(budget.TryAdmit(10));
        Assert.Equal(2, budget.Active);
        budget.Release(10);
        Assert.Equal(1, budget.Active);
        Assert.True(budget.TryAdmit(10));
        Assert.True(budget.TryAdmit(20)); Assert.True(budget.TryAdmit(20));
        Assert.Equal(4, budget.Active);
        Assert.False(budget.TryAdmit(30));
        Assert.Equal(4, budget.Active);
        budget.Release(20);
        Assert.True(budget.TryAdmit(30));
        Assert.Equal(4, budget.Active);
    }

    [Fact]
    public void ControlServicePassesCallerIdentityVerdictToServeAsync()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "winclient", "WinClient.App", "Hosting", "ControlService.cs"));
        // 服务宿主按调用者程序路径与安装根判定可信，并把判定结果传给协议层。
        Assert.Contains("var trusted = CallerIdentity.IsTrusted(PipePeer.ProcessImage(admitted), UpdatePlanner.DefaultAppRoot);", source);
        Assert.Contains("server.ServeAsync(pipe, lifetime.Token, trusted)", source);
        Assert.Contains("来自安装目录之外的程序连接了后台服务，只允许查询", source);
        Assert.DoesNotContain("Process.Start", source);
    }

    [Fact]
    public void ApplicationAndCoreNeverDirectlyReferenceOrUseEventLogging()
    {
        var root = RepositoryRoot();
        foreach (var name in new[] { "WinClient.Core", "WinClient.App" })
        {
            var directory = Path.Combine(root, "winclient", name);
            var project = XDocument.Load(Path.Combine(directory, name + ".csproj"));
            Assert.DoesNotContain(project.Descendants("PackageReference"), reference => (string?)reference.Attribute("Include") == "System.Diagnostics.EventLog");
            foreach (var file in Directory.GetFiles(directory, "*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(directory, file).Split(Path.DirectorySeparatorChar);
                if (relative.Contains("bin") || relative.Contains("obj")) continue;
                Assert.DoesNotContain("EventLog", File.ReadAllText(file));
            }
        }
    }

    internal static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "winclient", "WinClient.sln"))) return directory.FullName;
        throw new DirectoryNotFoundException("找不到受测仓库。");
    }
}
