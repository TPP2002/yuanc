using System.IO;
using System.IO.Pipes;
using System.ServiceProcess;
using Microsoft.Win32;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.Logging;
using WinClient.Core.Update;

namespace WinClient.App.Hosting;

public sealed class UpdateWindowsHost : IUpdateHost
{
    public static RedactingLog Log { get; } = new(new RollingFileLog(Path.Combine(ClientSettings.DataDirectory, "run", "update.log")));
    public DateTimeOffset Now => DateTimeOffset.UtcNow;
    public bool DesiredConnection => new DesiredStateStore().Read() == true;
    public Task DelayAsync(TimeSpan delay, CancellationToken token) => Task.Delay(delay, token);
    public async Task<bool> WaitServiceAsync(bool running, TimeSpan timeout, CancellationToken token)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            try
            {
                using var service = new ServiceController(ServiceInstaller.ServiceName);
                if (service.Status == (running ? ServiceControllerStatus.Running : ServiceControllerStatus.Stopped)) return true;
            }
            catch (InvalidOperationException) { return false; }
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(250, Math.Max(0, (timeout - clock.Elapsed).TotalMilliseconds))), token).ConfigureAwait(false);
        }
        return false;
    }
    public async Task<ControlResponse?> ReadStatusAsync(CancellationToken token)
    {
        using var pipe = new NamedPipeClientStream(".", ControlService.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(token).ConfigureAwait(false);
            using var client = new ControlClient(pipe);
            return await client.SendAsync("status", cancellationToken: token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException) { return null; }
    }
    public void SetRunValue(string executable)
    {
        using var key = Registry.LocalMachine.CreateSubKey(ServiceInstaller.RunKey, writable: true);
        key.SetValue(ServiceInstaller.RunValueName, ServiceInstaller.RunValue(executable), RegistryValueKind.String);
    }
    public static Task<int> ApplyAsync()
    {
        var store = new UpdateStore();
        if (store.ReadPending() is not { } pending || !string.Equals(pending.OldExe, InstallerRunner.CurrentExecutable, StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(2);
        return new UpdateApplier(store, new CommandRunner(), new UpdateWindowsHost(), UpdatePlanner.DefaultAppRoot, Environment.SystemDirectory, Log).RunAsync();
    }
}
