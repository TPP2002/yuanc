using WinClient.Core.Hosting;

namespace WinClient.Core.Update;

public sealed record UpdatePlan(string TargetExe, string[] KeepDirectories, string[] DeleteDirectories);

public static class UpdatePlanner
{
    public static string DefaultAppRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "YuanC", "app");
    public static string Executable(string appRoot, string version) => Path.Combine(Path.GetFullPath(appRoot), new UpdateVersion(version).Value, "YuanC-Client.exe");
    public static bool IsVersionDirectory(string appRoot, string directory)
    {
        var path = Path.GetFullPath(directory);
        if (!string.Equals(Path.GetDirectoryName(path), Path.TrimEndingDirectorySeparator(Path.GetFullPath(appRoot)), StringComparison.OrdinalIgnoreCase)) return false;
        try { _ = new UpdateVersion(Path.GetFileName(path)); return true; }
        catch (InvalidDataException) { return false; }
    }
    public static UpdatePlan Plan(string appRoot, string currentDirectory, string newVersion, IEnumerable<string> directories, UpdatePending? pending = null)
    {
        var current = Path.GetFullPath(currentDirectory);
        if (!IsVersionDirectory(appRoot, current)) throw new InvalidDataException("当前安装目录不正确，未更新。");
        var target = Executable(appRoot, newVersion);
        var versions = directories.Select(Path.GetFullPath).Where(p => IsVersionDirectory(appRoot, p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current, Path.GetDirectoryName(target)! };
        if (string.Equals(current, Path.GetDirectoryName(target), StringComparison.OrdinalIgnoreCase))
        {
            var previous = versions.Where(p => new UpdateVersion(Path.GetFileName(p)).CompareTo(new UpdateVersion(newVersion)) < 0)
                .OrderByDescending(p => new UpdateVersion(Path.GetFileName(p))).FirstOrDefault();
            if (previous is not null) keep.Add(previous);
        }
        if (pending is not null) { keep.Add(Path.GetDirectoryName(pending.OldExe)!); keep.Add(Path.GetDirectoryName(pending.NewExe)!); }
        return new(target, keep.ToArray(), versions.Where(p => !keep.Contains(p)).ToArray());
    }
    public static string[] Configure(string executable) => ServiceInstaller.Configure(executable, true);
    public static string[] Start() => ServiceInstaller.Start();
    public static string[] Stop() => ServiceInstaller.Stop();
}
