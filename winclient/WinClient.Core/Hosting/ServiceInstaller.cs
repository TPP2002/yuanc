using System.Diagnostics;

namespace WinClient.Core.Hosting;

/// <summary>Installation plan only. The elevated App executes these commands.</summary>
public static class ServiceInstaller
{
    public const string ServiceName = "YuanCService";
    public const string DisplayName = "YuanC 澳洲出口连接服务";
    public const string Description = "保持澳洲出口隧道与断网保护在后台运行";
    public const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string RunValueName = "YuanC";

    public static string ReleaseVersion(string informationalVersion)
    {
        var version = informationalVersion.Split('+')[0];
        if (string.IsNullOrWhiteSpace(version) || version is "." or ".." || version.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || version.Contains('/') || version.Contains('\\'))
            throw new ArgumentException("程序版本无效。");
        return version;
    }
    public static string InstalledExecutable(string programFiles, string informationalVersion) =>
        Path.Combine(Path.GetFullPath(programFiles), "YuanC", "app", ReleaseVersion(informationalVersion), "YuanC-Client.exe");
    public static string ServiceCommand(string executable) => $"\"{Path.GetFullPath(executable)}\" --service";
    public static string RunValue(string executable) => $"\"{Path.GetFullPath(executable)}\" --tray";
    public static bool ShouldCopy(string sourceSha256, string? destinationSha256) =>
        !string.Equals(sourceSha256, destinationSha256, StringComparison.OrdinalIgnoreCase);

    public static string[] Configure(string executable, bool exists) =>
        [exists ? "config" : "create", ServiceName, "binPath=", ServiceCommand(executable), "start=", "auto", "depend=", "BFE", "DisplayName=", DisplayName, "obj=", "LocalSystem"];
    public static string[] Describe() => ["description", ServiceName, Description];
    public static string[] FailureActions() => ["failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"];
    public static string[] FailureFlag() => ["failureflag", ServiceName, "1"];
    public static string[] Start() => ["start", ServiceName];
    public static string[] Stop() => ["stop", ServiceName];
    public static string[] Delete() => ["delete", ServiceName];

    public static ProcessStartInfo CreateStartInfo(string systemDirectory, IEnumerable<string> arguments)
    {
        var directory = Path.GetFullPath(systemDirectory);
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(directory, "sc.exe"), WorkingDirectory = directory,
            CreateNoWindow = true, UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        return info;
    }
}
