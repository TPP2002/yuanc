using System.Text.RegularExpressions;

namespace WinClient.Core.Client;

/// <summary>仅指定程序模式里一项名单的连带范围:Pattern 给隧道内核匹配,Executables 给过滤层逐个加过滤器。</summary>
public sealed record AppScope(string Selected, string Pattern, IReadOnlyList<string> Executables, bool Expanded)
{
    public static AppScope Exact(string path) => new(path, RoutingRenderer.PathPattern(path), [path], false);
}

public sealed record AppScopeFolders(string Windows, string ProgramFiles, string ProgramFilesX86, string LocalAppData,
    string RoamingAppData, string UserProfile, string ProgramData);

public interface IAppScopeFileSystem
{
    /// <summary>返回根目录下(最多 maxDepth 层)的 .exe 完整路径,跳过重解析点,最多 limit 个。</summary>
    IReadOnlyList<string> EnumerateExecutables(string root, int maxDepth, int limit);
}

public sealed class SystemAppScopeFileSystem : IAppScopeFileSystem
{
    public IReadOnlyList<string> EnumerateExecutables(string root, int maxDepth, int limit)
    {
        var result = new List<string>();
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("安装目录不存在。");
        Walk(root, 0);
        return result;

        void Walk(string directory, int depth)
        {
            if (result.Count >= limit) return;
            try
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*.exe"))
                {
                    if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) continue;
                    result.Add(file);
                    if (result.Count >= limit) return;
                }
                if (depth >= maxDepth) return;
                foreach (var child in Directory.EnumerateDirectories(directory))
                {
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
                    Walk(child, depth + 1);
                    if (result.Count >= limit) return;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { } // 个别子目录读不了就跳过。
        }
    }
}

public static class AppScopeResolver
{
    public const int MaxDepth = 4;
    public const int MaxExecutables = 64;

    private static readonly Regex Version = new(@"^(app-)?\d+(\.\d+){1,3}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Store = new(@"^(?<name>[^_\\]+)_\d+(\.\d+){1,3}_[^_\\]*__(?<pub>[a-z0-9]+)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static AppScopeFolders SystemFolders() => new(
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows),
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles),
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFilesX86),
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData),
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile),
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData));

    public static AppScope Resolve(string selected, AppScopeFolders folders, IAppScopeFileSystem fs)
    {
        var parts = selected.Split('\\');
        // 只处理 X:\...\x.exe 形式;其他形式(网络路径等)不扩。
        if (parts.Length < 3 || parts[0].Length != 2 || !char.IsAsciiLetter(parts[0][0]) || parts[0][1] != ':' || parts.Any(part => part.Length == 0))
            return AppScope.Exact(selected);
        var dirParts = parts[..^1];
        string root, pattern;
        var found = false; root = pattern = "";
        for (var level = 0; level < 3 && !found; level++)
        {
            var index = dirParts.Length - 1 - level;
            if (index < 1) break; // 到盘符为止。
            var name = dirParts[index];
            if (Version.IsMatch(name))
            {
                root = string.Join('\\', dirParts[..index]);
                pattern = "(?i)^" + RoutingRenderer.Escape(root) + @"\\.+\.exe$";
                found = true;
            }
            else if (Store.Match(name) is { Success: true } match)
            {
                root = string.Join('\\', dirParts[..(index + 1)]);
                var parent = string.Join('\\', dirParts[..index]);
                pattern = "(?i)^" + RoutingRenderer.Escape(parent) + @"\\" + RoutingRenderer.Escape(match.Groups["name"].Value)
                    + @"_[^\\]+__" + RoutingRenderer.Escape(match.Groups["pub"].Value) + @"\\.+\.exe$";
                found = true;
            }
        }
        if (!found)
        {
            root = string.Join('\\', dirParts);
            pattern = "(?i)^" + RoutingRenderer.Escape(root) + @"\\.+\.exe$";
        }
        if (TooBroad(root, folders)) return AppScope.Exact(selected);
        IReadOnlyList<string> listed;
        try { listed = fs.EnumerateExecutables(root, MaxDepth, MaxExecutables + 1); }
        catch (Exception) { return AppScope.Exact(selected); }
        if (listed.Count > MaxExecutables) return AppScope.Exact(selected);
        var all = new[] { selected }.Concat(listed).Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase).ToArray();
        return new(selected, pattern, all, true);
    }

    private static bool TooBroad(string root, AppScopeFolders folders)
    {
        var text = root.TrimEnd('\\');
        if (text.Split('\\').Length <= 2) return true; // 盘符根或盘符下只有一级。
        var windowsApps = string.IsNullOrEmpty(folders.ProgramFiles) ? "" : folders.ProgramFiles.TrimEnd('\\') + @"\WindowsApps";
        var broad = new[] { folders.Windows, folders.ProgramFiles, folders.ProgramFilesX86, folders.LocalAppData,
            folders.RoamingAppData, folders.UserProfile, folders.ProgramData, windowsApps };
        if (broad.Any(item => !string.IsNullOrEmpty(item) && string.Equals(item.TrimEnd('\\'), text, StringComparison.OrdinalIgnoreCase)))
            return true;
        var windows = folders.Windows?.TrimEnd('\\') ?? "";
        return windows.Length > 0 && text.StartsWith(windows + "\\", StringComparison.OrdinalIgnoreCase);
    }
}
