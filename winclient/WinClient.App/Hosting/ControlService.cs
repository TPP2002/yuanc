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
    // 管道实例数与监听任务数一致；每个客户端进程最多占 2 条，单个程序占不满全部实例。
    public const int MaxInstances = 16;
    public const int MaxPerClient = 2;
    private static readonly TimeSpan RejectLogInterval = TimeSpan.FromMinutes(5);
    private readonly ConnectionBudget budget = new(MaxInstances, MaxPerClient);
    private readonly Dictionary<uint, DateTime> rejectLogged = [];
    private readonly Dictionary<uint, DateTime> untrustedLogged = [];
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
                try { DataDirectorySecurity.EnsureHardened(ClientSettings.DataDirectory); }
                catch (InvalidOperationException ex)
                {
                    try { Log.Write("数据目录权限异常，后台服务拒绝启动：" + ex.Message); }
                    finally { Fatal(); }
                    return;
                }
                var updateStore = new UpdateStore();
                UpdateRecovery.Run(updateStore, InstallerRunner.CurrentExecutable, new UpdateWindowsHost(), UpdatePlanner.DefaultAppRoot, UpdateWindowsHost.Log);
                var secure = Path.Combine(ClientSettings.DataDirectory, "secure");
                var desired = new DesiredStateStore();
                var keep = desired.Read() != false;
                runtime = await ClientRuntime.CreateAsync(new KernelInstaller(new EmbeddedKernelSource()), secure, DataProtectionScope.LocalMachine, keepProtection: keep).ConfigureAwait(false);
                if (runtime.RecoveryWarning is { } warning) Log.Write("启动时断网保护降级恢复：" + warning);
                if (lifetime.IsCancellationRequested) return;
                // Expose status while connecting: network delay must not look like a dead new service.
                var initializing = InitializeRuntimeAsync(keep);
                if (lifetime.IsCancellationRequested) return;
                var version = ServiceInstaller.ReleaseVersion(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion);
                updateSource = new HttpUpdateSource();
                updates = new UpdateCoordinator(updateSource, updateStore, () => runtime.Snapshot, () => DateTimeOffset.UtcNow, version, Log);
                updates.Start();
                var server = new ControlServer(runtime, desired, updates, version);
                // 首实例独占管道名：若已有别的程序先建了同名管道，创建失败，服务拒绝启动而不是与冒名者共用名字。
                NamedPipeServerStream first;
                try { first = CreatePipe(PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    try { Log.Write("管道名已被其他程序占用，后台服务拒绝启动"); }
                    finally { Fatal(); }
                    return;
                }
                if (lifetime.IsCancellationRequested) { first.Dispose(); return; }
                Log.Write("后台服务已启动。");
                await Task.WhenAll(Enumerable.Range(0, MaxInstances).Select(i => ListenAsync(server, i == 0 ? first : null)).Append(initializing)).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
            catch (Exception) { Fatal(); }
        });
    }

    private async Task InitializeRuntimeAsync(bool keep)
    {
        try { await runtime!.Controller.InitializeAsync(autoConnect: keep, keepProtection: keep).ConfigureAwait(false); }
        catch (Exception) { Fatal(); }
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

    private static NamedPipeServerStream CreatePipe(PipeOptions options) =>
        NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, MaxInstances,
            PipeTransmissionMode.Byte, options, 4096, 4096, CreatePipeSecurity());

    private async Task ListenAsync(ControlServer server, NamedPipeServerStream? first)
    {
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                // 只有服务启动时同步建好的首实例带独占标志，之后的实例都不带。
                var created = first ?? CreatePipe(PipeOptions.Asynchronous);
                first = null;
                using var pipe = created;
                pipes.TryAdd(pipe, 0);
                try
                {
                    await pipe.WaitForConnectionAsync(lifetime.Token).ConfigureAwait(false);
                    var clientProcessId = PipePeer.ClientProcessId(pipe);
                    if (clientProcessId is not { } admitted || !budget.TryAdmit(admitted))
                    {
                        // 取不到进程号或超额：直接断开，不交给协议层。
                        LogRejected(clientProcessId);
                        continue;
                    }
                    try
                    {
                        // 调用者核验：程序位于本产品安装目录之下才可执行会改变连接状态的指令；
                        // 不可信连接照常服务（只读指令可用），首次出现时记一行日志。只查询，不起进程。
                        var trusted = CallerIdentity.IsTrusted(PipePeer.ProcessImage(admitted), UpdatePlanner.DefaultAppRoot);
                        if (!trusted) LogUntrusted(admitted);
                        await server.ServeAsync(pipe, lifetime.Token, trusted).ConfigureAwait(false);
                    }
                    finally { budget.Release(admitted); }
                }
                catch (IOException) { /* A client may disappear before completing its connection. */ }
                finally { pipes.TryRemove(pipe, out _); }
            }
        }
        catch (Exception ex) when (lifetime.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or IOException) { }
        catch (Exception) { Fatal(); }
        finally { first?.Dispose(); }
    }

    private void LogRejected(uint? clientProcessId)
    {
        if (!ShouldLog(rejectLogged, clientProcessId ?? 0)) return;
        try { Log.Write($"同一程序的管道连接数超限，已拒绝（进程 {(clientProcessId is { } id ? id.ToString(System.Globalization.CultureInfo.InvariantCulture) : "未知")}）"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* 日志写不进不能让监听循环退出。 */ }
    }

    private void LogUntrusted(uint clientProcessId)
    {
        if (!ShouldLog(untrustedLogged, clientProcessId)) return;
        try { Log.Write($"来自安装目录之外的程序连接了后台服务，只允许查询（进程 {clientProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)}）"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* 日志写不进不能让监听循环退出。 */ }
    }

    // 同一进程五分钟内只记一次，防止恶意程序反复连接刷满日志；顺带清掉过期的记录。
    private static bool ShouldLog(Dictionary<uint, DateTime> logged, uint key)
    {
        var now = DateTime.UtcNow;
        lock (logged)
        {
            if (logged.TryGetValue(key, out var last) && now - last < RejectLogInterval) return false;
            foreach (var stale in logged.Where(item => now - item.Value >= RejectLogInterval).Select(item => item.Key).ToList())
                logged.Remove(stale);
            logged[key] = now;
            return true;
        }
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
