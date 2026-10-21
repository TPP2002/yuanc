using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using WinClient.Core.Firewall;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.State;
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
        static string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(file)); }
        if (ServiceInstaller.ShouldCopy(Hash(CurrentExecutable), File.Exists(destination) ? Hash(destination) : null))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(CurrentExecutable, destination, overwrite: true);
            if (ServiceInstaller.ShouldCopy(Hash(CurrentExecutable), Hash(destination))) throw SafeError("程序复制校验失败，请重新安装。");
        }
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
        await StartAsync();
    }

    private async Task StartAsync()
    {
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
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        { Console.Error.WriteLine("无法联系后台服务，已跳过主动断开；已有断网保护可能仍在，请联系管理员处理。"); }
        if (connected)
        {
            using var client = new ControlClient(pipe);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var response = await client.SendAsync("disconnect", cancellationToken: timeout.Token);
            if (!response.Ok || response.Snapshot is not { ProtectionActive: false, State: ConnectionState.Disconnected })
                throw SafeError("未能撤销断网保护，卸载已停止，请联系管理员。");
        }
        var status = ServiceStatus();
        if (status is not null)
        {
            if (status != ServiceControllerStatus.Stopped)
            {
                if (status != ServiceControllerStatus.StopPending) await RunCommandAsync(ServiceInstaller.Stop(), "停止后台服务失败。");
                await WaitForAsync(ServiceControllerStatus.Stopped);
            }
            await RunCommandAsync(ServiceInstaller.Delete(), "删除后台服务失败。");
        }
        using var key = Registry.LocalMachine.OpenSubKey(ServiceInstaller.RunKey, writable: true);
        key?.DeleteValue(ServiceInstaller.RunValueName, throwOnMissingValue: false);
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
}
