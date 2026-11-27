using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinClient.Core.Process;

/// <summary>进程表里的一项：进程号与映像全路径（取不到时为 null）。</summary>
public sealed record KernelProcessInfo(int Id, string? ImagePath);

public interface IKernelProcessTable
{
    IReadOnlyList<KernelProcessInfo> FindByName(string processName);
    bool Kill(int id, TimeSpan wait);
}

/// <summary>真实系统进程表：按名字枚举，结束整棵进程树。</summary>
public sealed class SystemKernelProcessTable : IKernelProcessTable
{
    // winnt.h：PROCESS_QUERY_LIMITED_INFORMATION
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public IReadOnlyList<KernelProcessInfo> FindByName(string processName)
    {
        var result = new List<KernelProcessInfo>();
        foreach (var process in System.Diagnostics.Process.GetProcessesByName(processName))
        {
            using (process) result.Add(new KernelProcessInfo(process.Id, TryReadImagePath(process.Id)));
        }
        return result;
    }

    public bool Kill(int id, TimeSpan wait)
    {
        System.Diagnostics.Process process;
        try { process = System.Diagnostics.Process.GetProcessById(id); }
        catch (ArgumentException) { return true; } // 进程本来就不存在。
        using (process)
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) { return true; } // 刚好已退出。
            catch (Win32Exception) { return false; } // 拒绝访问等，等不到就交给调用方报错。
            return process.WaitForExit(wait);
        }
    }

    private static string? TryReadImagePath(int id)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, id);
        if (process.IsInvalid) return null;
        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        if (!QueryFullProcessImageNameW(process, 0, buffer, ref size)) return null;
        return size == 0 ? null : new string(buffer, 0, (int)size);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);
}

/// <summary>
/// 结束本产品上次残留的连接内核。只认两种：映像全路径与要启动的内核完全相同，
/// 或位于本产品的内核目录（含各版本子目录）且文件名为 sing-box.exe；别的同名程序一个都不动。
/// </summary>
public sealed class StrayKernelSweeper(IKernelProcessTable? table = null)
{
    public const string NotStoppedMessage = "上次残留的连接内核没能结束，请重启电脑后再连接。";
    private static readonly TimeSpan KillWait = TimeSpan.FromSeconds(5);
    private readonly IKernelProcessTable processTable = table ?? new SystemKernelProcessTable();

    public int Sweep(string executablePath, string? ownedDirectory, Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var processName = Path.GetFileNameWithoutExtension(executablePath);
        var target = SafeFullPath(executablePath);
        var owned = ownedDirectory is null ? null : SafeFullPath(ownedDirectory);
        var stopped = 0;
        var failed = false;
        foreach (var info in processTable.FindByName(processName))
        {
            if (info.Id == Environment.ProcessId) continue;
            if (info.ImagePath is null) continue;
            if (!IsOwnedKernel(info.ImagePath, target, owned)) continue;
            if (processTable.Kill(info.Id, KillWait)) stopped++;
            else failed = true;
        }
        if (stopped > 0) log?.Invoke($"已结束上次残留的连接内核 {stopped} 个。");
        if (failed) throw new IOException(NotStoppedMessage);
        return stopped;
    }

    private static bool IsOwnedKernel(string imagePath, string? target, string? ownedDirectory)
    {
        var image = SafeFullPath(imagePath);
        if (image is null) return false;
        if (target is not null && string.Equals(image, target, StringComparison.OrdinalIgnoreCase)) return true;
        if (ownedDirectory is null) return false;
        var prefix = ownedDirectory.EndsWith(Path.DirectorySeparatorChar)
            ? ownedDirectory
            : ownedDirectory + Path.DirectorySeparatorChar;
        if (!image.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        return string.Equals(Path.GetFileName(image), "sing-box.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static string? SafeFullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }
}
