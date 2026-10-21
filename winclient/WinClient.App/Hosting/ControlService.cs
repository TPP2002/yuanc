using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using WinClient.Core.Client;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.Kernel;
using WinClient.Core.Logging;
using WinClient.Core.Update;
using System.Reflection;
using TimeoutException = System.TimeoutException;

namespace WinClient.App.Hosting;

public sealed class ControlService : ServiceBase
{
    public const string PipeName = "YuanC-Control";
    private readonly CancellationTokenSource lifetime = new();
    private readonly ConcurrentDictionary<NamedPipeServerStream, byte> pipes = new();
    private static readonly RedactingLog Log = new(new RollingFileLog(Path.Combine(ClientSettings.DataDirectory, "run", "service.log")));
    private Task? hosting;
    private ClientRuntime? runtime;
    private UpdateCoordinator? updates;
    private HttpUpdateSource? updateSource;
    private int stopped;

    public ControlService()
    {
        ServiceName = ServiceInstaller.ServiceName;
        CanStop = true; CanShutdown = true; AutoLog = false;
        AppDomain.CurrentDomain.UnhandledException += Unhandled;
        TaskScheduler.UnobservedTaskException += Unobserved;
    }

    protected override void OnStart(string[] args)
    {
        RequestAdditionalTime(30000);
        hosting = Task.Run(async () =>
        {
            try
            {
                var updateStore = new UpdateStore();
                PrepareSecureDirectory(updateStore.Root);
                UpdateRecovery.Run(updateStore, InstallerRunner.CurrentExecutable, new UpdateWindowsHost(), UpdatePlanner.DefaultAppRoot, UpdateWindowsHost.Log);
                var secure = Path.Combine(ClientSettings.DataDirectory, "secure");
                PrepareSecureDirectory(secure);
                runtime = await ClientRuntime.CreateAsync(new KernelInstaller(new EmbeddedKernelSource()), secure, DataProtectionScope.LocalMachine).ConfigureAwait(false);
                if (runtime.RecoveryWarning is { } warning) Log.Write("启动时断网保护降级恢复：" + warning);
                if (lifetime.IsCancellationRequested) return;
                var desired = new DesiredStateStore();
                // Expose status while connecting: network delay must not look like a dead new service.
                var initializing = InitializeRuntimeAsync(desired);
                if (lifetime.IsCancellationRequested) return;
                var version = ServiceInstaller.ReleaseVersion(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion);
                updateSource = new HttpUpdateSource();
                updates = new UpdateCoordinator(updateSource, updateStore, () => runtime.Snapshot, () => DateTimeOffset.UtcNow, version, Log);
                updates.Start();
                var server = new ControlServer(runtime, desired, updates, version);
                Log.Write("后台服务已启动。");
                await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => ListenAsync(server)).Append(initializing)).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
            catch (Exception) { Fatal(); }
        });
    }

    private async Task InitializeRuntimeAsync(DesiredStateStore desired)
    {
        try { await runtime!.Controller.InitializeAsync(autoConnect: desired.Read() != false).ConfigureAwait(false); }
        catch (Exception) { Fatal(); }
    }

    public static void PrepareSecureDirectory(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        // Set the restrictive descriptor before any secret is loaded or written.
        Directory.CreateDirectory(path).SetAccessControl(security);
    }

    public static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    private async Task ListenAsync(ControlServer server)
    {
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                using var pipe = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, 4,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, CreatePipeSecurity());
                pipes.TryAdd(pipe, 0);
                try
                {
                    await pipe.WaitForConnectionAsync(lifetime.Token).ConfigureAwait(false);
                    await server.ServeAsync(pipe, lifetime.Token).ConfigureAwait(false);
                }
                catch (IOException) { /* A client may disappear before completing its connection. */ }
                finally { pipes.TryRemove(pipe, out _); }
            }
        }
        catch (Exception ex) when (lifetime.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or IOException) { }
        catch (Exception) { Fatal(); }
    }

    protected override void OnStop() { RequestAdditionalTime(30000); StopRuntime(); }
    protected override void OnShutdown() => StopRuntime();
    private void StopRuntime()
    {
        if (Interlocked.Exchange(ref stopped, 1) != 0) return;
        try
        {
            lifetime.Cancel();
            updates?.Cancel();
            foreach (var pipe in pipes.Keys) pipe.Dispose();
            if (hosting is not null && !hosting.Wait(TimeSpan.FromSeconds(25))) throw new TimeoutException();
            if (updates is not null && !updates.StopAsync().Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException();
            updates?.Dispose(); updateSource?.Dispose();
            runtime?.Dispose(); // No disconnect command: protection remains in place.
            Log.Write("后台服务已停止，已有断网保护保持。");
        }
        catch (Exception) { Fatal(); }
    }
    public static void LogFatal()
    {
        try { Log.Write("后台服务发生异常，已停止运行，等待系统重新启动。"); }
        catch (Exception) { /* Logging failure must not turn a fatal exit into success. */ }
    }
    private void Fatal() { ExitCode = 1; LogFatal(); Environment.Exit(1); }
    private void Unhandled(object sender, UnhandledExceptionEventArgs args) => Fatal();
    private void Unobserved(object? sender, UnobservedTaskExceptionEventArgs args) => Fatal();
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            AppDomain.CurrentDomain.UnhandledException -= Unhandled;
            TaskScheduler.UnobservedTaskException -= Unobserved;
            lifetime.Dispose();
        }
        base.Dispose(disposing);
    }
}
