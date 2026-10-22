namespace WinClient.Core.Ipc;

/// <summary>
/// 管道服务端身份的纯判定（不含系统调用，便于单测）：
/// 服务端会话号等于期望会话号，且程序完整路径规范化后严格位于 appRoot 之下。
/// 原始路径或规范化路径含 ".." 段、路径为空或不是完整路径、等于 appRoot 本身，一律判不可信。
/// </summary>
public static class ServerIdentity
{
    /// <param name="serverSessionId">管道服务端进程所在会话号。</param>
    /// <param name="clientSessionId">期望的会话号；本产品后台是系统服务，调用方传 0。</param>
    public static bool IsTrusted(uint serverSessionId, uint clientSessionId, string? imagePath, string appRoot)
    {
        if (serverSessionId != clientSessionId) return false;
        return IsImageUnderRoot(imagePath, appRoot);
    }

    /// <summary>
    /// 路径部分的纯判定（服务端身份与调用者身份共用）：程序完整路径非空、是完整路径，
    /// 原始与规范化后都不含 ".." 段，规范化后严格位于 appRoot 之下（不等于 appRoot 本身，比较不分大小写）。
    /// </summary>
    internal static bool IsImageUnderRoot(string? imagePath, string appRoot)
    {
        if (string.IsNullOrEmpty(imagePath) || string.IsNullOrEmpty(appRoot)) return false;
        if (!Path.IsPathFullyQualified(imagePath) || HasParentSegment(imagePath)) return false;
        string full, root;
        try { full = Path.GetFullPath(imagePath); root = Path.GetFullPath(appRoot); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException) { return false; }
        if (HasParentSegment(full)) return false;
        var prefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;
        return full.Length > prefix.Length && full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasParentSegment(string path) =>
        path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Contains("..");
}
