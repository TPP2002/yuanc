using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using WinClient.Core.Client;
using WinClient.Core.Network;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using WinClient.Core.Update;
using TimeoutException = System.TimeoutException;

namespace WinClient.App.Hosting;

public sealed class InstallerRunner
{
    private readonly ICommandRunner runner = new CommandRunner();
    public static ServiceControllerStatus? ServiceStatus()
    {
        using var service = new ServiceController(ServiceInstaller.ServiceName);
        try { return service.Status; }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: 1060 }) { return null; }
    }
    public static string CurrentExecutable => Path.GetFullPath(Environment.ProcessPath ?? throw new InvalidOperationException("找不到客户端程序。"));

    /// <summary>只读服务登记的程序路径；读不到或不是本产品的启动命令时返回 null。</summary>
    public static string? RegisteredServiceExecutable()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceInstaller.ServiceName);
            return UiHandover.ServiceExecutable(key?.GetValue("ImagePath") as string);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    public static UiHandoverDecision HandoverDecision()
    {
        var informational = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        string version;
        try { version = informational is null ? "" : ServiceInstaller.ReleaseVersion(informational); }
        catch (ArgumentException) { version = ""; }
        return UiHandover.Decide(CurrentExecutable, version, UpdatePlanner.DefaultAppRoot,
            RegisteredServiceExecutable(), File.Exists, UiHandover.SameContent);
    }

    public static ProcessStartInfo ElevationInfo(string action)
    {
        if (action is not ("--install" or "--repair" or "--uninstall")) throw new ArgumentException("安装操作无效。");
        return new ProcessStartInfo
        {
            FileName = CurrentExecutable, WorkingDirectory = Path.GetDirectoryName(CurrentExecutable)!,
            Arguments = action, Verb = "runas", UseShellExecute = true, CreateNoWindow = true
        };
    }
    public static async Task<bool> ElevateAsync(string action)
    {
        using var process = System.Diagnostics.Process.Start(ElevationInfo(action)) ?? throw new InvalidOperationException("无法打开安装程序。");
        await process.WaitForExitAsync();
        return process.ExitCode == 0;
    }

    public async Task<int> RunAsync(string action)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("此操作需要管理员确认，请从客户端窗口点击安装或修复。");
            switch (action)
            {
                case "--install": await InstallAsync(); break;
                case "--repair": await StartAsync(); break;
                case "--uninstall": await UninstallAsync(); break;
                default: throw new InvalidOperationException("安装操作无效。");
            }
            return 0;
        }
        catch (InvalidOperationException ex) when (ex.Data.Contains("safe") || ex.Message.StartsWith("此操作需要管理员确认", StringComparison.Ordinal))
        { Console.Error.WriteLine(ex.Message); return 1; }
        catch (Exception)
        { Console.Error.WriteLine("操作未完成，请检查管理员权限、安装目录和后台服务状态，再重试或联系管理员。"); return 1; }
    }

    private async Task InstallAsync()
    {
        var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? throw SafeError("无法读取客户端版本。");
        var destination = ServiceInstaller.InstalledExecutable(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), version);
        var previous = RegisteredServiceExecutable();
        static string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(file)); }
        if (ServiceInstaller.ShouldCopy(Hash(CurrentExecutable), File.Exists(destination) ? Hash(destination) : null))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(CurrentExecutable, destination, overwrite: true);
            if (ServiceInstaller.ShouldCopy(Hash(CurrentExecutable), Hash(destination))) throw SafeError("程序复制校验失败，请重新安装。");
        }
        EnsureDataDirectory();
        await RunCommandAsync(ServiceInstaller.Configure(destination, ServiceStatus() is not null), "配置后台服务失败。");
        await RunCommandAsync(ServiceInstaller.Describe(), "设置后台服务说明失败。");
        await RunCommandAsync(ServiceInstaller.FailureActions(), "设置后台服务自动重启失败。");
        await RunCommandAsync(ServiceInstaller.FailureFlag(), "启用后台服务自动重启失败。");
        using (var key = Registry.LocalMachine.CreateSubKey(ServiceInstaller.RunKey, writable: true))
        {
            var value = ServiceInstaller.RunValue(destination);
            if (!string.Equals(key.GetValue(ServiceInstaller.RunValueName) as string, value, StringComparison.Ordinal))
                key.SetValue(ServiceInstaller.RunValueName, value, RegistryValueKind.String);
        }
        if (ServiceInstaller.SwitchesExecutable(previous, destination)) await StartSwitchedAsync(previous);
        else await StartAsync();
    }

    /// <summary>服务原来登记的是另一份程序：先停服务，再启动新版并确认稳定；失败时改回旧版。</summary>
    private async Task StartSwitchedAsync(string? previous)
    {
        await StopServiceAsync();
        try
        {
            await StartAsync();
            await Task.Delay(TimeSpan.FromSeconds(3));
            if (ServiceStatus() == ServiceControllerStatus.Running) return;
            throw SafeError("新版本的后台服务未能启动，已改回原来的版本。");
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or
            Win32Exception or TimeoutException or OperationCanceledException)
        {
            if (previous is null || !File.Exists(previous)) throw;
            await RunCommandAsync(ServiceInstaller.Configure(previous, true), "改回原来的后台服务失败。");
            using (var key = Registry.LocalMachine.CreateSubKey(ServiceInstaller.RunKey, writable: true))
                key.SetValue(ServiceInstaller.RunValueName, ServiceInstaller.RunValue(previous), RegistryValueKind.String);
            try { await StartAsync(); }
            catch (Exception) { /* 改回旧版的启动失败只吞掉，仍报原来的失败。 */ }
            throw SafeError("新版本的后台服务未能启动，已改回原来的版本。");
        }
    }

    private async Task StartAsync()
    {
        EnsureDataDirectory();
        var status = ServiceStatus() ?? throw SafeError("后台服务尚未安装，请先安装。");
        if (status == ServiceControllerStatus.Running) return;
        if (status == ServiceControllerStatus.StopPending) await WaitForAsync(ServiceControllerStatus.Stopped);
        if (ServiceStatus() != ServiceControllerStatus.StartPending)
            await RunCommandAsync(ServiceInstaller.Start(), "启动后台服务失败。");
        await WaitForAsync(ServiceControllerStatus.Running);
    }

    private async Task UninstallAsync()
    {
        // Only a deliberate uninstall requests disconnect; stopping the service alone never does.
        using var pipe = new NamedPipeClientStream(".", ControlService.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connected = false;
        try { await pipe.ConnectAsync(3000); connected = true; }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException) { }
        if (connected && !PipePeer.VerifyServer(pipe, UpdatePlanner.DefaultAppRoot))
        {
            // 连到的不是本产品的后台服务：不向它发任何指令，断开后按未联系上处理。
            Console.Error.WriteLine("后台服务身份核验失败，按未联系上处理。");
            pipe.Dispose();
            connected = false;
        }
        if (connected)
        {
            using var client = new ControlClient(pipe);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var response = await client.SendAsync("disconnect", cancellationToken: timeout.Token);
            if (!response.Ok || response.Snapshot is not { ProtectionActive: false, State: ConnectionState.Disconnected })
                throw SafeError("未能撤销断网保护，卸载已停止，请联系管理员。");
            await StopServiceAsync();
        }
        else
        {
            // 管道被占满或被冒名时服务不可达：先停服务（避免它再加规则），再由卸载程序自己撤掉断网保护。
            Console.Error.WriteLine("无法联系后台服务，将在停止服务后直接恢复网络。");
            await StopServiceAsync();
            try { await new KillSwitchApplier(Path.Combine(ClientSettings.DataDirectory, "run"), wfp: WfpEngine.CreateProduction(), routes: new RouteGuard()).RemoveAsync(); }
            catch (Exception)
            {
                // 撤防失败时保留服务与自启值：下次开机服务仍能按期望状态接管保护，比留一套没人管的阻止规则安全。
                throw SafeError("未能撤销断网保护，卸载已停止，请联系管理员。");
            }
            // 撤防之后恢复连接期间关掉的网卡 IPv6 绑定;失败只提示,卸载继续。
            try
            {
                var nicWarning = await new NicGuard(Path.Combine(ClientSettings.DataDirectory, "run"), new SystemAdapterProbe()).RestoreAsync();
                if (nicWarning is not null) Console.Error.WriteLine(nicWarning);
            }
            catch (Exception)
            {
                Console.Error.WriteLine("网卡的 IPv6 未能恢复,请重试或联系管理员。");
            }
        }
        if (ServiceStatus() is not null) await RunCommandAsync(ServiceInstaller.Delete(), "删除后台服务失败。");
        using var key = Registry.LocalMachine.OpenSubKey(ServiceInstaller.RunKey, writable: true);
        key?.DeleteValue(ServiceInstaller.RunValueName, throwOnMissingValue: false);
    }
    private async Task StopServiceAsync()
    {
        var status = ServiceStatus();
        if (status is null || status == ServiceControllerStatus.Stopped) return;
        if (status != ServiceControllerStatus.StopPending) await RunCommandAsync(ServiceInstaller.Stop(), "停止后台服务失败。");
        await WaitForAsync(ServiceControllerStatus.Stopped);
    }
    private async Task RunCommandAsync(string[] arguments, string error)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = await runner.RunAsync(ServiceInstaller.CreateStartInfo(Environment.SystemDirectory, arguments), timeout.Token);
        if (result.ExitCode != 0) throw SafeError(error);
    }
    private static async Task WaitForAsync(ServiceControllerStatus expected)
    {
        var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed < TimeSpan.FromSeconds(30))
        {
            if (ServiceStatus() == expected) return;
            await Task.Delay(250);
        }
        throw SafeError("等待后台服务响应超时，请稍后重试。");
    }
    private static InvalidOperationException SafeError(string message)
    {
        var error = new InvalidOperationException(message); error.Data["safe"] = true; return error;
    }

    private static void EnsureDataDirectory()
    {
        try { DataDirectorySecurity.EnsureHardened(ClientSettings.DataDirectory); }
        catch (Exception) { throw SafeError("数据目录权限设置失败，请以管理员身份重试或联系管理员。"); }
    }
}
