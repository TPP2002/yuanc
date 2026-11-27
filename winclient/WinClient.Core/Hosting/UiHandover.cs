using System.IO;
using System.Security.Cryptography;
using WinClient.Core.Ipc;
using WinClient.Core.Update;

namespace WinClient.Core.Hosting;

public enum UiHandoverKind { Stay, Handover, Upgrade, Reinstall }

public sealed record UiHandoverDecision(UiHandoverKind Kind, string? Target = null, string? InstalledVersion = null);

/// <summary>界面换位的纯判定：只算路径、版本号与文件内容，不起进程、不读注册表。</summary>
public static class UiHandover
{
    private const string ServiceSuffix = " --service";

    /// <summary>服务登记的启动命令必须是「半角双引号 + 完整路径 + 半角双引号 + 一个空格 + --service」。</summary>
    public static string? ServiceExecutable(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return null;
        var text = imagePath.Trim();
        if (!text.EndsWith(ServiceSuffix, StringComparison.Ordinal)) return null;
        var quoted = text[..^ServiceSuffix.Length];
        if (quoted.Length < 2 || quoted[0] != '"' || quoted[^1] != '"') return null;
        var path = quoted[1..^1];
        if (path.Length == 0 || path.Contains('"')) return null;
        return Path.IsPathFullyQualified(path) ? path : null;
    }

    public static UiHandoverDecision Decide(string currentExecutable, string currentVersion, string appRoot,
        string? serviceExecutable, Func<string, bool> exists, Func<string, string, bool> sameContent)
    {
        if (ServerIdentity.IsImageUnderRoot(currentExecutable, appRoot)) return new(UiHandoverKind.Stay);
        if (string.IsNullOrEmpty(serviceExecutable) ||
            !ServerIdentity.IsImageUnderRoot(serviceExecutable, appRoot) ||
            !exists(serviceExecutable))
            return new(UiHandoverKind.Reinstall);
        var target = Path.GetFullPath(serviceExecutable);
        if (sameContent(currentExecutable, serviceExecutable)) return new(UiHandoverKind.Handover, target);
        var installed = Path.GetFileName(Path.GetDirectoryName(target)) ?? "";
        if (TryParse(currentVersion, out var current) && TryParse(installed, out var installedVersion) &&
            current.CompareTo(installedVersion) > 0)
            return new(UiHandoverKind.Upgrade, target, installed);
        return new(UiHandoverKind.Handover, target);
    }

    /// <summary>长度相同且 SHA256 相同才算内容相同；任一文件不存在或读不了都算不同。</summary>
    public static bool SameContent(string first, string second)
    {
        try
        {
            using var firstStream = File.OpenRead(first);
            using var secondStream = File.OpenRead(second);
            if (firstStream.Length != secondStream.Length) return false;
            return SHA256.HashData(firstStream).SequenceEqual(SHA256.HashData(secondStream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private static bool TryParse(string value, out UpdateVersion version)
    {
        try { version = new UpdateVersion(value); return true; }
        catch (InvalidDataException) { version = null!; return false; }
    }
}
