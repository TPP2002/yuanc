using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using WinClient.Core.Client;
using WinClient.Core.State;
using WinClient.Core.Kernel;

namespace WinClient.App;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private ClientRuntime? runtime;
    private ClientSnapshot snapshot = new(ConnectionState.Disconnected, "未连接", "", false);
    private string code = "";
    public string Code { get => code; set { code = value; Notify(); } }
    public string Status => snapshot.Status;
    public string Message => snapshot.Message;
    public string Mode => "当前模式：" + snapshot.Mode;
    public bool IsBusy { get; private set; }
    public string ConnectLabel => snapshot.ProtectionActive || snapshot.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting ? "断开" : "连接";
    public ICommand RedeemCommand { get; }
    public ICommand ConnectCommand { get; }
    public ICommand ImportPairingCommand { get; }
    public ICommand ClearPairingCommand { get; }
    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel(Func<string?> choosePairingFile)
    {
        RedeemCommand = new AsyncCommand(() => RunAsync(async () =>
        { await runtime!.Controller.RedeemAsync(Code); Code = ""; }), () => runtime is not null && !IsBusy);
        ConnectCommand = new AsyncCommand(() => RunAsync(() => ConnectLabel == "断开"
            ? runtime!.Controller.DisconnectAsync() : runtime!.Controller.ConnectAsync()), () => runtime is not null && !IsBusy);
        ImportPairingCommand = new AsyncCommand(() => RunAsync(async () =>
        {
            var path = choosePairingFile();
            if (path is not null) await runtime!.ImportPairingAsync(await System.IO.File.ReadAllTextAsync(path));
        }), CanChangePairing);
        ClearPairingCommand = new AsyncCommand(() => RunAsync(() => runtime!.ClearPairingAsync()),
            () => CanChangePairing() && snapshot.Mode == "自用模式");
    }
    private bool CanChangePairing() => runtime is not null && !IsBusy && !snapshot.ProtectionActive &&
        snapshot.State is not (ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting);
    public async Task InitializeAsync() => await RunAsync(async () =>
    {
        runtime = await ClientRuntime.CreateAsync(new KernelInstaller(new EmbeddedKernelSource()));
        runtime.Controller.Changed += Update;
        await runtime.Controller.InitializeAsync();
        Update(runtime.Controller.Snapshot);
    });
    private async Task RunAsync(Func<Task> action)
    {
        IsBusy = true; Notify(nameof(IsBusy)); CommandManager.InvalidateRequerySuggested();
        try { await action(); }
        catch (System.IO.InvalidDataException ex)
        { Update(snapshot with { Message = ex.Message }); }
        catch (InvalidOperationException ex) when (ex.Message == KernelInstaller.VerificationFailureMessage)
        { Update(snapshot with { Status = "需人工处理", Message = ex.Message }); }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException or
            System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException or ArgumentException or OperationCanceledException)
        { Update(snapshot with { Status = "需人工处理", Message = "操作未完成，请检查服务器配置和恢复记录，或联系管理员。" }); }
        finally { IsBusy = false; Notify(nameof(IsBusy)); CommandManager.InvalidateRequerySuggested(); }
    }
    private void Update(ClientSnapshot value)
    {
        if (!Application.Current.Dispatcher.CheckAccess()) { Application.Current.Dispatcher.InvokeAsync(() => Update(value)); return; }
        snapshot = value;
        Notify(nameof(Status)); Notify(nameof(Message)); Notify(nameof(ConnectLabel)); Notify(nameof(Mode));
        CommandManager.InvalidateRequerySuggested();
    }
    public void ExportAudit(string path)
    {
        try
        {
            if (runtime is null) throw new InvalidOperationException();
            runtime.ExportFirewallAudit(path);
            Update(snapshot with { Message = "已导出防火墙审计；完整诊断功能尚未提供。" });
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException)
        { Update(snapshot with { Message = "尚无可导出的审计记录，或所选位置无法写入。" }); }
    }
    private void Notify([CallerMemberName] string? property = null) => PropertyChanged?.Invoke(this, new(property));
    public void Dispose()
    {
        if (runtime is not null) runtime.Controller.Changed -= Update;
        runtime?.Dispose();
    }

    private sealed class AsyncCommand(Func<Task> execute, Func<bool> canExecute) : ICommand
    {
        public bool CanExecute(object? parameter) => canExecute();
        public async void Execute(object? parameter) { if (CanExecute(parameter)) await execute(); }
        public event EventHandler? CanExecuteChanged
        { add => CommandManager.RequerySuggested += value; remove => CommandManager.RequerySuggested -= value; }
    }
}
