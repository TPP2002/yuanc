using System.Diagnostics;

namespace WinClient.Core.Firewall;

public sealed record CommandResult(int ExitCode, string Output, string Error = "");
public interface ICommandRunner
{
    Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default);
}

public sealed class CommandRunner : ICommandRunner
{
    public async Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
    {
        startInfo.CreateNoWindow = true;
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        using var process = new System.Diagnostics.Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException("无法启动防火墙管理程序。");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var standardOutput = await output.ConfigureAwait(false);
            var standardError = await error.ConfigureAwait(false);
            // 标准错误原文只留在内存里；要进日志必须先经 KillSwitchApplier.SanitizeError 脱敏。
            return new(process.ExitCode, standardOutput, standardError);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }
}
