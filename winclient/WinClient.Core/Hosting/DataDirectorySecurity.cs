using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WinClient.Core.Hosting;

[SupportedOSPlatform("windows")]
public static class DataDirectorySecurity
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static void Harden(string path)
    {
        var directory = Directory.CreateDirectory(path);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(AdministratorsSid);
        foreach (var sid in new[] { SystemSid, AdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(security);
    }

    public static string? Evaluate(SecurityIdentifier? owner, IEnumerable<FileSystemAccessRule> rules, bool isReparsePoint)
    {
        if (isReparsePoint) return "目录是重解析点。";
        if (!Trusted(owner)) return "目录所有者不是系统或管理员。";
        foreach (var rule in rules)
        {
            var sid = rule.IdentityReference as SecurityIdentifier
                ?? (SecurityIdentifier)rule.IdentityReference.Translate(typeof(SecurityIdentifier));
            if (rule.AccessControlType == AccessControlType.Allow && !Trusted(sid))
                return "目录允许系统和管理员以外的身份访问。";
            if (rule.AccessControlType == AccessControlType.Deny && Trusted(sid))
                return "目录拒绝系统或管理员访问。";
        }
        return null;
    }

    public static string? Verify(string path)
    {
        try
        {
            if (IsReparsePoint(path)) return Evaluate(null, [], true);
            if (!Directory.Exists(path)) return "目录不存在。";
            var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            return Evaluate(security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier,
                security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return "无法读取目录所有者或权限。";
        }
    }

    public static void EnsureHardened(string root)
    {
        foreach (var relative in new[] { ".", "run", "secure", "updates", "bin" })
        {
            var path = relative == "." ? root : Path.Combine(root, relative);
            if (relative == "bin" && !Path.Exists(path)) continue;
            var reason = Verify(path);
            if (reason is null) continue;
            try
            {
                if (!IsReparsePoint(path))
                {
                    Harden(path);
                    reason = Verify(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
            {
                reason = "无法修正目录所有者或权限。";
            }
            if (reason is not null)
                throw new InvalidOperationException($"数据目录权限异常，已拒绝启动：{relative} {reason}");
        }
    }

    public static bool IsTrustedOwner(string filePath) =>
        Trusted(new FileInfo(filePath).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier);

    private static bool Trusted(SecurityIdentifier? sid) => sid is not null && (sid.Equals(SystemSid) || sid.Equals(AdministratorsSid));

    private static bool IsReparsePoint(string path)
    {
        try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
}
