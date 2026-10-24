using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Hosting;
using Xunit;

namespace WinClient.Tests;

public sealed class DataDirectorySecurityTests
{
    private static SecurityIdentifier Sid(WellKnownSidType type) => new(type, null);
    private static FileSystemAccessRule Rule(WellKnownSidType type, AccessControlType access = AccessControlType.Allow) =>
        new(Sid(type), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, access);
    private static FileSystemAccessRule[] TrustedRules() =>
        [Rule(WellKnownSidType.LocalSystemSid), Rule(WellKnownSidType.BuiltinAdministratorsSid)];

    [Theory]
    [InlineData(WellKnownSidType.LocalSystemSid)]
    [InlineData(WellKnownSidType.BuiltinAdministratorsSid)]
    public void TrustedOwnersAndRulesPass(WellKnownSidType owner) =>
        Assert.Null(DataDirectorySecurity.Evaluate(Sid(owner), TrustedRules(), false));

    [Fact]
    public void UsersOwnerIsRejected() =>
        Assert.NotNull(DataDirectorySecurity.Evaluate(Sid(WellKnownSidType.BuiltinUsersSid), TrustedRules(), false));

    [Fact]
    public void MissingOwnerIsRejected() => Assert.NotNull(DataDirectorySecurity.Evaluate(null, TrustedRules(), false));

    [Fact]
    public void ExtraUsersAllowIsRejected() =>
        Assert.NotNull(DataDirectorySecurity.Evaluate(Sid(WellKnownSidType.LocalSystemSid),
            TrustedRules().Append(Rule(WellKnownSidType.BuiltinUsersSid)), false));

    [Theory]
    [InlineData(WellKnownSidType.LocalSystemSid)]
    [InlineData(WellKnownSidType.BuiltinAdministratorsSid)]
    public void TrustedIdentityDenyIsRejected(WellKnownSidType denied) =>
        Assert.NotNull(DataDirectorySecurity.Evaluate(Sid(WellKnownSidType.LocalSystemSid),
            TrustedRules().Append(Rule(denied, AccessControlType.Deny)), false));

    [Fact]
    public void ReparsePointIsRejected() =>
        Assert.NotNull(DataDirectorySecurity.Evaluate(Sid(WellKnownSidType.LocalSystemSid), TrustedRules(), true));

    [AdministratorFact]
    public void HardenSetsExactProtectedAclAndAdministratorOwner()
    {
        using var directory = new TempDirectory();
        DataDirectorySecurity.Harden(directory.Path);
        Assert.Null(DataDirectorySecurity.Verify(directory.Path));
        var security = new DirectoryInfo(directory.Path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(Sid(WellKnownSidType.BuiltinAdministratorsSid), security.GetOwner(typeof(SecurityIdentifier)));
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.Equal(2, rules.Length);
        Assert.Equal(TrustedRules().Select(rule => rule.IdentityReference.Value).Order(), rules.Select(rule => rule.IdentityReference.Value).Order());
        Assert.All(rules, rule =>
        {
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            Assert.Equal(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, rule.InheritanceFlags);
            Assert.Equal(PropagationFlags.None, rule.PropagationFlags);
            Assert.False(rule.IsInherited);
        });
    }

    [AdministratorFact]
    public void EnsureHardenedRepairsUsersWriteAccessAndChecksExistingBin()
    {
        using var directory = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(directory.Path, "bin"));
        var security = new DirectoryInfo(directory.Path).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Sid(WellKnownSidType.BuiltinUsersSid), FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory.Path).SetAccessControl(security);
        Assert.NotNull(DataDirectorySecurity.Verify(directory.Path));
        DataDirectorySecurity.EnsureHardened(directory.Path);
        foreach (var name in new[] { "", "run", "secure", "updates", "bin" })
            Assert.Null(DataDirectorySecurity.Verify(Path.Combine(directory.Path, name)));
    }

    [Fact]
    public void UntrustedConfigOwnerIsRejectedBeforeReadingJson()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, "server.json");
        File.WriteAllText(path, "不是有效配置");
        var error = Assert.Throws<InvalidDataException>(() => ClientSettings.Load(directory.Path,
            ownerIsTrusted: candidate => { Assert.Equal(path, candidate); return false; }));
        Assert.Contains("所有者", error.Message);
    }

    [Fact]
    public void TrustedConfigOwnerCanLoad()
    {
        using var directory = new TempDirectory();
        WriteSettings(directory.Path, null);
        var called = false;
        var settings = ClientSettings.Load(directory.Path, ownerIsTrusted: _ => { called = true; return true; });
        Assert.True(called);
        Assert.Equal("https://192.0.2.1", settings!.ServerUrl);
    }

    [Fact]
    public void KernelOutsideInstallationRootIsRejectedIncludingSiblingPrefix()
    {
        using var directory = new TempDirectory();
        var root = Path.Combine(directory.Path, "install");
        foreach (var path in new[] { Path.Combine(directory.Path, "fake.exe"), root + "-other/fake.exe", Path.Combine(root, "..", "fake.exe") })
        {
            WriteSettings(directory.Path, path);
            Assert.Contains("安装目录", Assert.Throws<InvalidDataException>(() => ClientSettings.Load(directory.Path, kernelRoot: root)).Message);
        }
    }

    [Fact]
    public void KernelInsideInstallationRootAllowsCaseAndSeparatorNormalization()
    {
        using var directory = new TempDirectory();
        var root = Path.Combine(directory.Path, "install");
        var path = Path.Combine(root, "kernel", "fake.exe");
        WriteSettings(directory.Path, path);
        Assert.Equal(path, ClientSettings.Load(directory.Path, kernelRoot: root.ToUpperInvariant().Replace('\\', '/') + "/")!.SingBoxPath);
    }

    [Fact]
    public void OmittedKernelRootStillRestrictsToProgramFiles()
    {
        using var directory = new TempDirectory();
        WriteSettings(directory.Path, Path.Combine(directory.Path, "fake.exe"));
        Assert.Contains("安装目录", Assert.Throws<InvalidDataException>(() => ClientSettings.Load(directory.Path)).Message);
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "YuanC", "kernel", "fake.exe");
        WriteSettings(directory.Path, path);
        Assert.Equal(path, ClientSettings.Load(directory.Path)!.SingBoxPath);
    }

    [Fact]
    public void RelativeKernelPathKeepsExistingError()
    {
        using var directory = new TempDirectory();
        WriteSettings(directory.Path, "relative.exe");
        Assert.Equal("连接内核必须配置为绝对路径。",
            Assert.Throws<InvalidDataException>(() => ClientSettings.Load(directory.Path, kernelRoot: directory.Path)).Message);
    }

    private static void WriteSettings(string root, string? kernel) => File.WriteAllText(Path.Combine(root, "server.json"),
        JsonSerializer.Serialize(new { server_url = "https://192.0.2.1", server_spki_sha256 = Convert.ToBase64String(new byte[32]), sing_box_path = kernel }));
}

public sealed class AdministratorFactAttribute : FactAttribute
{
    public AdministratorFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) { Skip = "真实目录权限测试需要 Windows 管理员进程。"; return; }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            Skip = "当前测试进程不是管理员，无法设置管理员所有者；真实目录权限测试已跳过。";
    }
}
