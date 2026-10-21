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

    private sealed class Child(System.Diagnostics.Process process) : ISingBoxProcess
    {
        public void Stop()
        {
            if (process.HasExited) return;
            process.Kill(entireProcessTree: true);
            if (!process.WaitForExit(5000))
                throw new TimeoutException("连接内核未能在限定时间内停止，断网保护必须保留。");
        }
        public void Dispose() => process.Dispose();
    }
}
