using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.ServiceProcess;
using System.Windows;
using System.Windows.Input;
using WinClient.App.Hosting;
using WinClient.Core.Client;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using TimeoutException = System.TimeoutException;

namespace WinClient.App;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private enum Availability { Unavailable, NeedInstall, NeedRepair, Ready }
    private Availability availability;
    private ControlClient? client;
    private bool disposed;
    private readonly CancellationTokenSource lifetime = new();
    private ClientSnapshot snapshot = new(ConnectionState.Disconnected, "正在检查后台服务", "", false);
    private string serviceVersion = "";
    private string updateMessage = "";
    private string code = "";
    public string Code { get => code; set { code = value; Notify(); } }
    public string Status => snapshot.Status;
    public string Message => snapshot.Message + (serviceVersion.Length != 0 && serviceVersion != ControlSnapshot.CurrentVersion
        ? $" 后台已更新到 {serviceVersion}，下次打开界面将使用新版" : "");
    public string ServiceVersion => serviceVersion.Length == 0 ? "后台版本：等待连接" : "后台版本 " + serviceVersion;
    public string UpdateMessage => updateMessage;
    public string Mode => "当前模式：" + snapshot.Mode;
    public bool IsBusy { get; private set; }
    public bool CanUseConnection => client is not null && availability == Availability.Ready && !IsBusy;
    private bool ShouldDisconnect => snapshot.ProtectionActive || snapshot.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting;
    public string ConnectLabel => availability switch
    {
        Availability.NeedInstall => "安装后台服务(需管理员确认一次)",
        Availability.NeedRepair => "修复",
        Availability.Ready => ShouldDisconnect ? "断开" : "连接",
        _ => "重试"
    };
    public ICommand RedeemCommand { get; }
    public ICommand ConnectCommand { get; }
    public ICommand ImportPairingCommand { get; }
    public ICommand ClearPairingCommand { get; }
    public ICommand CheckUpdateCommand { get; }
    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel(Func<string?> choosePairingFile)
    {
        CheckUpdateCommand = new AsyncCommand(() => RunAsync(() => SendAsync("check_update")), () => CanUseConnection);
        RedeemCommand = new AsyncCommand(() => RunAsync(async () =>
        { await SendAsync("redeem", Code); Code = ""; }), () => CanUseConnection);
        ConnectCommand = new AsyncCommand(() => RunAsync(MainActionAsync), () => !IsBusy);
        ImportPairingCommand = new AsyncCommand(() => RunAsync(async () =>
        {
            var path = choosePairingFile();
            if (path is not null) await SendAsync("import_pairing", pairingJson: await File.ReadAllTextAsync(path, lifetime.Token));
        }), CanChangePairing);
        ClearPairingCommand = new AsyncCommand(() => RunAsync(() => SendAsync("clear_pairing")),
            () => CanChangePairing() && snapshot.Mode == "自用模式");
    }
    private bool CanChangePairing() => CanUseConnection && !ShouldDisconnect;
    public Task InitializeAsync() => RunAsync(InitializeCoreAsync);
    private async Task InitializeCoreAsync()
    {
        DropClient();
        var status = InstallerRunner.ServiceStatus();
        if (status is null)
        {
            availability = Availability.NeedInstall;
            Update(snapshot with { Status = "需安装后台服务", Message = "首次使用请安装后台服务，确认一次管理员权限后即可使用。" });
            return;
        }
        if (status != ServiceControllerStatus.Running)
        {
            availability = Availability.NeedRepair;
            Update(snapshot with { Status = "后台服务未运行", Message = "请点击修复以启动后台服务。" });
            return;
        }
        // First attempt plus five retries, each with the specified three-second pipe timeout.
        for (var attempt = 0; attempt <= 5; attempt++)
        {
            lifetime.Token.ThrowIfCancellationRequested();
            var pipe = new NamedPipeClientStream(".", ControlService.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync(3000, lifetime.Token);
                client = new ControlClient(pipe);
                client.SnapshotChanged += UpdateProtocol;
                client.ConnectionClosed += OnConnectionClosed;
                var response = await client.SendAsync("subscribe", cancellationToken: lifetime.Token);
                if (!response.Ok || response.Snapshot is null) throw new IOException();
                availability = Availability.Ready;
                UpdateProtocol(response.Snapshot);
                return;
            }
            catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
            {
                DropClient(); pipe.Dispose();
                if (attempt < 5) await Task.Delay(1000, lifetime.Token);
            }
        }
        availability = Availability.Unavailable;
        Update(snapshot with { Status = "无法连接后台服务", Message = "无法连接后台服务,请重启电脑或联系管理员" });
    }
    private async Task MainActionAsync()
    {
        if (availability is Availability.NeedInstall or Availability.NeedRepair)
        {
            var action = availability == Availability.NeedInstall ? "--install" : "--repair";
            if (!await InstallerRunner.ElevateAsync(action))
            {
                Update(snapshot with { Message = "操作未完成，请重试或联系管理员。" });
                return;
            }
            await InitializeCoreAsync();
        }
        else if (availability == Availability.Ready) await SendAsync(ShouldDisconnect ? "disconnect" : "connect");
        else await InitializeCoreAsync();
    }
    public Task ConnectFromTrayAsync() => CanUseConnection ? RunAsync(() => SendAsync("connect")) : Task.CompletedTask;
    public Task DisconnectFromTrayAsync() => CanUseConnection ? RunAsync(() => SendAsync("disconnect")) : Task.CompletedTask;
    private async Task SendAsync(string op, string? code = null, string? pairingJson = null)
    {
        var response = await (client ?? throw new IOException()).SendAsync(op, code, pairingJson, lifetime.Token);
        if (response.Snapshot is not null) UpdateProtocol(response.Snapshot);
        if (!response.Ok) Update(snapshot with { Message = response.Error ?? "操作未完成，请联系管理员。" });
    }
    private async Task RunAsync(Func<Task> action)
    {
        if (disposed) return;
        IsBusy = true; Refresh();
        try { await action(); }
        catch (OperationCanceledException) when (disposed) { }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        { Update(snapshot with { Message = "已取消管理员确认，可稍后重试。" }); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException or
            System.Text.Json.JsonException or ArgumentException or OperationCanceledException or TimeoutException or Win32Exception)
        { Update(snapshot with { Message = "操作未完成，请检查后台服务或联系管理员。" }); }
        finally { IsBusy = false; Refresh(); }
    }
    private void OnConnectionClosed()
    {
        var dispatcher = Application.Current.Dispatcher;
        if (disposed || dispatcher.HasShutdownStarted) return;
        dispatcher.InvokeAsync(() =>
        {
            if (disposed) return;
            availability = Availability.Unavailable;
            Update(snapshot with { Status = "后台服务连接已中断", Message = "请点击重试；连接与断网保护由后台服务管理。" });
        });
    }
    private void Update(ClientSnapshot value)
    {
        if (disposed || Application.Current.Dispatcher.HasShutdownStarted) return;
        if (!Application.Current.Dispatcher.CheckAccess()) { Application.Current.Dispatcher.InvokeAsync(() => Update(value)); return; }
        snapshot = value; Refresh();
    }
    private void UpdateProtocol(ControlSnapshot value)
    {
        if (disposed || Application.Current.Dispatcher.HasShutdownStarted) return;
        if (!Application.Current.Dispatcher.CheckAccess()) { Application.Current.Dispatcher.InvokeAsync(() => UpdateProtocol(value)); return; }
        serviceVersion = value.ServiceVersion; updateMessage = value.Update.Message;
        Update(value);
    }
    private void Refresh()
    {
        if (disposed) return;
        Notify(nameof(Status)); Notify(nameof(Message)); Notify(nameof(ConnectLabel)); Notify(nameof(Mode)); Notify(nameof(IsBusy)); Notify(nameof(CanUseConnection));
        Notify(nameof(ServiceVersion)); Notify(nameof(UpdateMessage));
        CommandManager.InvalidateRequerySuggested();
    }
    public Task ExportAuditAsync(string path) => RunAsync(async () =>
    {
        var response = await (client ?? throw new IOException()).SendAsync("read_audit", cancellationToken: lifetime.Token);
        if (!response.Ok || response.Audit is null)
        {
            Update(snapshot with { Message = response.Error ?? "尚无可导出的审计记录，请完成一次连接后重试。" }); return;
        }
        await File.WriteAllTextAsync(path, response.Audit, lifetime.Token);
        Update(snapshot with { Message = "已导出防火墙审计；完整诊断功能尚未提供。" });
    });
    private void Notify([CallerMemberName] string? property = null) => PropertyChanged?.Invoke(this, new(property));
    private void DropClient()
    {
        if (client is null) return;
        client.SnapshotChanged -= UpdateProtocol; client.ConnectionClosed -= OnConnectionClosed;
        client.Dispose(); client = null;
    }
    public void Dispose() { disposed = true; lifetime.Cancel(); DropClient(); }

    private sealed class AsyncCommand(Func<Task> execute, Func<bool> canExecute) : ICommand
    {
        public bool CanExecute(object? parameter) => canExecute();
        public async void Execute(object? parameter) { if (CanExecute(parameter)) await execute(); }
        public event EventHandler? CanExecuteChanged
        { add => CommandManager.RequerySuggested += value; remove => CommandManager.RequerySuggested -= value; }
    }
}
