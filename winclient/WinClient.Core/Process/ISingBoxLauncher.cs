using System.ComponentModel;
using System.Diagnostics;

namespace WinClient.Core.Process;

public interface ISingBoxProcess : IDisposable
{
    void Stop();
}

public interface ISingBoxLauncher
{
    ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit);
}

public sealed class SingBoxLauncher : ISingBoxLauncher
{
    private const string BindFailedMessage = "连接内核未能绑定到后台服务，后台服务意外退出时它可能残留。";
    private static readonly object JobGate = new();

    /// <summary>
    /// 整个进程共用一个作业，第一次 Start 时建；本类不释放它，进程退出时系统关句柄，内核随之结束。
    /// 建失败时保持 null，下次 Start 再试。
    /// </summary>
    internal static KernelJob? SharedJob { get; private set; }

    public ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit)
    {
        // Enforce the invariant even if this launcher is used without the manager.
        startInfo.CreateNoWindow = true;
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        var process = new System.Diagnostics.Process { StartInfo = startInfo, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) onLog(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) onLog(e.Data); };
        process.Exited += (_, _) => onExit(process.ExitCode);
        var started = false;
        try
        {
            if (!process.Start()) throw new InvalidOperationException("无法启动连接内核。");
            started = true;
            // 进程起来后、开始读输出前绑定作业；失败只记一行，进程照常返回，由下次启动清理兜底。
            var job = EnsureSharedJob();
            var assigned = false;
            if (job is not null)
            {
                try { job.Assign(process); assigned = true; }
                catch (Win32Exception) { }
            }
            if (!assigned) onLog(BindFailedMessage);
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return new Child(process);
        }
        catch
        {
            if (started && !process.HasExited) process.Kill(entireProcessTree: true);
            process.Dispose();
            throw;
        }
    }

    private static KernelJob? EnsureSharedJob()
    {
        lock (JobGate)
        {
            if (SharedJob is not null) return SharedJob;
            try { SharedJob = KernelJob.Create(); }
            catch (Win32Exception) { SharedJob = null; }
            return SharedJob;
        }
    }

    internal sealed class Child : ISingBoxProcess
    {
        internal System.Diagnostics.Process Process { get; }

        internal Child(System.Diagnostics.Process process) => Process = process;

        public void Stop()
        {
            if (Process.HasExited) return;
            Process.Kill(entireProcessTree: true);
            if (!Process.WaitForExit(5000))
                throw new TimeoutException("连接内核未能在限定时间内停止，断网保护必须保留。");
        }
        public void Dispose() => Process.Dispose();
    }
}
