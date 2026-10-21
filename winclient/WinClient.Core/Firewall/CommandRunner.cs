using System.Diagnostics;

namespace WinClient.Core.Firewall;

public sealed record CommandResult(int ExitCode, string Output);
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
            // Error text can contain private paths; never send raw text to logs or UI.
            await error.ConfigureAwait(false);
            return new(process.ExitCode, standardOutput);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }
}
