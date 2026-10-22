using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
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
            // 连到的不是本产品的后台服务：与连不上同样处理，交给服务进程兜底判定。
            if (!PipePeer.VerifyServer(pipe, UpdatePlanner.DefaultAppRoot)) return null;
            using var client = new ControlClient(pipe);
            return await client.SendAsync("status", cancellationToken: token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException) { return null; }
    }
    public string? RunningServiceExecutable()
    {
        try
        {
            using var service = new ServiceController(ServiceInstaller.ServiceName);
            if (service.Status != ServiceControllerStatus.Running) return null;
        }
        catch (InvalidOperationException) { return null; }
        if (ServiceProcessId() is not { } processId || PipePeer.ProcessImage(processId) is not { } image) return null;
        try { return Path.GetFullPath(image); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException) { return null; }
    }
    private static uint? ServiceProcessId()
    {
        var manager = IntPtr.Zero;
        var service = IntPtr.Zero;
        try
        {
            manager = ServiceNative.OpenSCManagerW(null, null, ServiceNative.GenericRead);
            if (manager == IntPtr.Zero) return null;
            service = ServiceNative.OpenServiceW(manager, ServiceInstaller.ServiceName, ServiceNative.ServiceQueryStatus);
            if (service == IntPtr.Zero) return null;
            if (!ServiceNative.QueryServiceStatusEx(service, ServiceNative.ScStatusProcessInfo, out var status,
                (uint)Marshal.SizeOf<ServiceNative.ServiceStatusProcess>(), out _)) return null;
            return status.CurrentState == ServiceNative.ServiceRunning && status.ProcessId != 0 ? status.ProcessId : null;
        }
        finally
        {
            if (service != IntPtr.Zero) ServiceNative.CloseServiceHandle(service);
            if (manager != IntPtr.Zero) ServiceNative.CloseServiceHandle(manager);
        }
    }
    private static class ServiceNative
    {
        public const uint GenericRead = 0x80000000;
        public const uint ServiceQueryStatus = 0x0004;
        public const int ScStatusProcessInfo = 0;
        public const uint ServiceRunning = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern IntPtr OpenServiceW(IntPtr manager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out ServiceStatusProcess buffer, uint bufferSize, out uint bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr handle);
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
