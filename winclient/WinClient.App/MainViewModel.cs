using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.ServiceProcess;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using WinClient.App.Hosting;
using WinClient.App.Presentation;
using WinClient.Core.Client;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using WinClient.Core.Update;
using TimeoutException = System.TimeoutException;

namespace WinClient.App;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private ServiceAvailability availability;
    private ControlClient? client;
    private bool disposed;
    private readonly CancellationTokenSource lifetime = new();
    private readonly Func<string, CancellationToken, Task<string?>> runScript;
    private readonly Func<string, string?> publishVerifyPage;
    private ClientSnapshot snapshot = new(ConnectionState.Disconnected, "正在检查后台服务", "", false);
    private string serviceVersion = "";
    private string updateMessage = "";
    private string code = "";
    public string Code { get => code; set { code = value; Notify(); } }
    public string Status => snapshot.Status;
    public bool RoutingIsGlobal
    {
        get => snapshot.RoutingMode == "global";
        set { if (value && !RoutingIsGlobal) _ = RunAsync(() => SendAsync("set_routing", mode: "global", apps: snapshot.RoutingApps)); }
    }
    public bool RoutingIsApps
    {
        get => snapshot.RoutingMode == "apps";
        set { if (value && !RoutingIsApps) _ = RunAsync(() => SendAsync("set_routing", mode: "apps", apps: snapshot.RoutingApps)); }
    }
    public IReadOnlyList<string> RoutingApps => snapshot.RoutingApps;
    private string? selectedRoutingApp;
    public string? SelectedRoutingApp
    {
        get => selectedRoutingApp;
        set { selectedRoutingApp = value; Notify(); CommandManager.InvalidateRequerySuggested(); }
    }
    public bool CanChangeRouting => CanUseConnection && !ShouldDisconnect;
    public ICommand AddRoutingAppCommand { get; }
    public ICommand RemoveRoutingAppCommand { get; }
    public bool EnvironmentEnabled
    {
        get => snapshot.EnvironmentEnabled;
        set { if (value != snapshot.EnvironmentEnabled) _ = RunAsync(() => SendAsync("set_environment", enabled: value)); }
    }
    public string Message => snapshot.Message + (serviceVersion.Length != 0 && serviceVersion != ControlSnapshot.CurrentVersion
        ? $" 后台已更新到 {serviceVersion}，下次打开界面将使用新版" : "");

    public string UpdateMessage => updateMessage;

    public bool IsBusy { get; private set; }
    public bool CanUseConnection => client is not null && availability == ServiceAvailability.Ready && !IsBusy;
    public bool CanRestoreEnvironment => CanUseConnection && !ShouldDisconnect;
    public ICommand RestoreEnvironmentCommand { get; }
    private bool ShouldDisconnect => snapshot.ProtectionActive || snapshot.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting;
    public string ConnectLabel => IsBusy ? Hero.BusyLabel : Hero.PrimaryLabel;
    public ICommand RedeemCommand { get; }
    public ICommand ConnectCommand { get; }
    public ICommand ImportPairingCommand { get; }
    public ICommand ClearPairingCommand { get; }
    public ICommand CheckUpdateCommand { get; }
    public ICommand GoToAccountCommand { get; }
    public ICommand CreateBrowserProfileCommand { get; }
    public string BrowserProfileMessage { get; private set; } = "";
    public ICommand OpenVerifyPageCommand { get; }
    public string VerifyPageMessage { get; private set; } = "";
    public HeroPresentation Hero { get; private set; } = null!;
    private PageKind currentPage;
    public PageKind CurrentPage
    {
        get => currentPage;
        set
        {
            if (currentPage == value) return;
            currentPage = value; Notify();
            if (value == PageKind.Environment) _ = LoadSelfCheckAsync();
        }
    }
    public string ServiceStateText => "后台服务 · " + (availability switch
    {
        ServiceAvailability.Ready => "运行中", ServiceAvailability.NeedInstall => "未安装", ServiceAvailability.NeedRepair => "未运行",
        _ when snapshot.Status.Contains("身份核验失败") => "身份核验失败",
        _ when snapshot.Status.Contains("中断") => "已中断", _ => "未运行"
    });
    public Tone ServiceStateTone => availability switch
    {
        ServiceAvailability.Ready => Tone.Ok, ServiceAvailability.NeedInstall => Tone.N,
        ServiceAvailability.NeedRepair => Tone.Warn, _ => Tone.Bad
    };
    public string ServiceVersionText => serviceVersion.Length == 0 ? "" : "版本 " + serviceVersion;
    public string ServiceVersionDisplay => ServiceVersionText.Length == 0 ? "等待连接" : ServiceVersionText;
    public string ModeText => snapshot.Mode;
    public string CurrentVersion => ControlSnapshot.CurrentVersion;
    private UpdateStatus updateStatus = new();
    public string UpdateCheckedAtText => updateStatus.CheckedAt?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "尚未检查";
    public bool IsUpdateInProgress => updateStatus.Stage != "idle" && UpdateMessage.Length > 0;
    public string EnvironmentBadgeText => EnvironmentEnabled ? "已应用" : "未启用";
    public string SelfCheckStatus => snapshot.SelfCheckStatus;
    public Tone SelfCheckTone => Hero.Rows[2].Tile.Tone;
    public IReadOnlyList<SelfCheckItemView> SelfCheckItems { get; private set; } = [];
    public string SelfCheckCheckedAtText { get; private set; } = "";
    public string SelfCheckSummary { get; private set; } = "";
    private string observedSelfCheckStatus = "";
    private int selfCheckRequest;
    public string ConnectionDisabledReason => IsBusy ? "正在处理,请稍候。" : CanUseConnection ? "" : "后台服务未就绪,请先在「连接」页处理。";
    public string PairingDisabledReason => ConnectionDisabledReason.Length > 0 ? ConnectionDisabledReason : ShouldDisconnect ? "连接中不能更换配对文件,请先断开。" : "";
    public string ClearPairingDisabledReason => PairingDisabledReason.Length > 0 ? PairingDisabledReason : snapshot.Mode != "自用模式" ? "尚无可清除的本机配对文件。" : "";
    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel(Func<string?> choosePairingFile, Func<string?> chooseProgram,
        Func<string, CancellationToken, Task<string?>>? runScript = null,
        Func<string, string?>? publishVerifyPage = null)
    {
        this.runScript = runScript ?? RunBrowserScriptAsync;
        this.publishVerifyPage = publishVerifyPage ?? VerifyPagePublisher.WriteAndOpen;
        OpenVerifyPageCommand = new AsyncCommand(OpenVerifyPageAsync, () => !IsBusy);
        CreateBrowserProfileCommand = new AsyncCommand(CreateBrowserProfileAsync, () => !IsBusy);
        RestoreEnvironmentCommand = new AsyncCommand(() => RunAsync(() => SendAsync("restore_environment")), () => CanRestoreEnvironment);
        GoToAccountCommand = new AsyncCommand(() => { CurrentPage = PageKind.Account; return Task.CompletedTask; }, () => true);
        AddRoutingAppCommand = new AsyncCommand(() => RunAsync(async () =>
        {
            var path = chooseProgram();
            if (!string.IsNullOrWhiteSpace(path))
                await SendAsync("set_routing", mode: snapshot.RoutingMode, apps: [.. snapshot.RoutingApps, path]);
        }), () => CanChangeRouting);
        RemoveRoutingAppCommand = new AsyncCommand(() => RunAsync(() => SendAsync("set_routing", mode: snapshot.RoutingMode,
            apps: snapshot.RoutingApps.Where(path => !string.Equals(path, SelectedRoutingApp, StringComparison.OrdinalIgnoreCase)).ToArray())),
            () => CanChangeRouting && SelectedRoutingApp is not null);
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
        Refresh();
    }
    private bool CanChangePairing() => CanUseConnection && !ShouldDisconnect;
    private static async Task<string?> RunBrowserScriptAsync(string script, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        var result = await new CommandRunner().RunAsync(KillSwitchApplier.CreateStartInfo(script), timeout.Token);
        return result.ExitCode == 0 ? result.Output : null;
    }
    internal Task OpenVerifyPageAsync() => RunAsync(() =>
    {
        const string incomplete = "打开复核页未完成,请联系管理员。";
        try
        {
            var html = BrowserVerifyPage.Html(new(snapshot.RoutingMode, snapshot.EnvironmentEnabled));
            var path = publishVerifyPage(html);
            VerifyPageMessage = path is null ? incomplete
                : "已用默认浏览器打开复核页;要在澳洲专用浏览器里核对,把地址栏里的地址复制过去即可。页面文件:" + path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or
            InvalidOperationException or OperationCanceledException or PlatformNotSupportedException or NotSupportedException)
        { VerifyPageMessage = incomplete; }
        Notify(nameof(VerifyPageMessage));
        return Task.CompletedTask;
    });

    internal Task CreateBrowserProfileAsync() => RunAsync(async () =>
    {
        try
        {
            var output = await runScript(BrowserProfilePlanner.Script(), lifetime.Token);
            BrowserProfileMessage = BrowserProfilePlanner.Describe(output);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception or
            OperationCanceledException or UnauthorizedAccessException or JsonException)
        { BrowserProfileMessage = BrowserProfilePlanner.Describe(null); }
        Notify(nameof(BrowserProfileMessage));
    });
    public Task InitializeAsync() => RunAsync(InitializeCoreAsync);
    private async Task InitializeCoreAsync()
    {
        DropClient();
        var status = InstallerRunner.ServiceStatus();
        if (status is null)
        {
            availability = ServiceAvailability.NeedInstall;
            Update(snapshot with { Status = "需安装后台服务", Message = "首次使用请安装后台服务，确认一次管理员权限后即可使用。" });
            return;
        }
        if (status != ServiceControllerStatus.Running)
        {
            availability = ServiceAvailability.NeedRepair;
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
                // 发第一条指令前核验服务端身份；不过就断开且不再重试——重试只会再连到同一个冒名者。
                if (!PipePeer.VerifyServer(pipe, UpdatePlanner.DefaultAppRoot))
                {
                    pipe.Dispose();
                    availability = ServiceAvailability.Unavailable;
                    Update(snapshot with { Status = "后台服务身份核验失败", Message = "连接到的不是本产品的后台服务，已断开；请联系管理员。" });
                    return;
                }
                client = new ControlClient(pipe);
                client.SnapshotChanged += UpdateProtocol;
                client.ConnectionClosed += OnConnectionClosed;
                var response = await client.SendAsync("subscribe", cancellationToken: lifetime.Token);
                if (!response.Ok || response.Snapshot is null) throw new IOException();
                availability = ServiceAvailability.Ready;
                UpdateProtocol(response.Snapshot);
                return;
            }
            catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
            {
                DropClient(); pipe.Dispose();
                if (attempt < 5) await Task.Delay(1000, lifetime.Token);
            }
        }
        availability = ServiceAvailability.Unavailable;
        Update(snapshot with { Status = "无法连接后台服务", Message = "无法连接后台服务,请重启电脑或联系管理员" });
    }
    private async Task MainActionAsync()
    {
        if (availability is ServiceAvailability.NeedInstall or ServiceAvailability.NeedRepair)
        {
            var action = availability == ServiceAvailability.NeedInstall ? "--install" : "--repair";
            if (!await InstallerRunner.ElevateAsync(action))
            {
                Update(snapshot with { Message = "操作未完成，请重试或联系管理员。" });
                return;
            }
            await InitializeCoreAsync();
        }
        else if (availability == ServiceAvailability.Ready) await SendAsync(ShouldDisconnect ? "disconnect" : "connect");
        else await InitializeCoreAsync();
    }
    public Task ConnectFromTrayAsync() => CanUseConnection ? RunAsync(() => SendAsync("connect")) : Task.CompletedTask;
    public Task DisconnectFromTrayAsync() => CanUseConnection ? RunAsync(() => SendAsync("disconnect")) : Task.CompletedTask;
    private async Task SendAsync(string op, string? code = null, string? pairingJson = null, bool? enabled = null,
        string? mode = null, string[]? apps = null)
    {
        var response = await (client ?? throw new IOException()).SendAsync(op, code, pairingJson, lifetime.Token, enabled, mode, apps);
        if (response.Snapshot is not null) UpdateProtocol(response.Snapshot);
        if (!response.Ok)
        {
            if (op == "set_routing")
            {
                var actual = await client.SendAsync("status", cancellationToken: lifetime.Token);
                if (actual.Snapshot is not null) UpdateProtocol(actual.Snapshot);
                Refresh();
            }
            Update(snapshot with { Message = response.Error ?? "操作未完成，请联系管理员。" });
        }
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
        var dispatcher = Application.Current?.Dispatcher;
        if (disposed || dispatcher?.HasShutdownStarted == true) return;
        void Closed()
        {
            if (disposed) return;
            availability = ServiceAvailability.Unavailable;
            Update(snapshot with { Status = "后台服务连接已中断", Message = "请点击重试；连接与断网保护由后台服务管理。" });
        }
        if (dispatcher is null) Closed(); else dispatcher.InvokeAsync(Closed);
    }
    private void Update(ClientSnapshot value)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (disposed || dispatcher?.HasShutdownStarted == true) return;
        if (dispatcher is not null && !dispatcher.CheckAccess()) { dispatcher.InvokeAsync(() => Update(value)); return; }
        snapshot = value; Refresh();
    }
    private void UpdateProtocol(ControlSnapshot value)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (disposed || dispatcher?.HasShutdownStarted == true) return;
        if (dispatcher is not null && !dispatcher.CheckAccess()) { dispatcher.InvokeAsync(() => UpdateProtocol(value)); return; }
        serviceVersion = value.ServiceVersion; updateMessage = value.Update.Message; updateStatus = value.Update;
        Update(value);
    }
    public void ApplyPreview(ControlSnapshot snapshot, ServiceAvailability availability)
    {
        this.availability = availability;
        this.snapshot = snapshot;
        serviceVersion = snapshot.ServiceVersion; updateMessage = snapshot.Update.Message; updateStatus = snapshot.Update;
        Refresh();
    }
    public async Task LoadSelfCheckAsync()
    {
        var request = ++selfCheckRequest;
        var source = client;
        if (source is null) { ApplySelfCheckJson(null); return; }
        try
        {
            var response = await source.SendAsync("read_selfcheck", cancellationToken: lifetime.Token);
            if (disposed || request != selfCheckRequest || source != client) return;
            ApplySelfCheckJson(response.Ok ? response.SelfCheck : null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
            JsonException or ArgumentException or OperationCanceledException or TimeoutException)
        {
            if (!disposed && request == selfCheckRequest) ApplySelfCheckJson(null);
        }
    }
    internal void ApplySelfCheckJson(string? json)
    {
        IReadOnlyList<SelfCheckItemView> items = [];
        var checkedAt = "";
        var summary = "";
        try
        {
            if (!string.IsNullOrWhiteSpace(json))
            {
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                checkedAt = root.GetProperty("checked_at").GetString() ?? "";
                summary = root.GetProperty("summary").GetString() ?? "";
                var parsed = new List<SelfCheckItemView>();
                foreach (var item in root.GetProperty("items").EnumerateArray())
                {
                    var result = item.GetProperty("result").GetString();
                    if (result is not ("通过" or "未通过" or "跳过" or "无法核验")) throw new JsonException("自检结果无效");
                    parsed.Add(new(parsed.Count + 1, item.GetProperty("name").GetString() ?? "", result,
                        item.TryGetProperty("detail", out var detail) ? detail.GetString() ?? "" : ""));
                }
                items = parsed;
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException)
        { items = []; checkedAt = ""; summary = ""; }
        SelfCheckItems = items; SelfCheckCheckedAtText = checkedAt; SelfCheckSummary = summary;
        Notify(nameof(SelfCheckItems)); Notify(nameof(SelfCheckCheckedAtText)); Notify(nameof(SelfCheckSummary));
    }
    private void Refresh()
    {
        if (disposed) return;
        Notify(nameof(CanRestoreEnvironment));
        Hero = StatusPresentation.Build(snapshot, availability, ShouldDisconnect);
        Notify(nameof(Hero)); Notify(nameof(Status)); Notify(nameof(Message)); Notify(nameof(ConnectLabel)); Notify(nameof(ModeText)); Notify(nameof(IsBusy)); Notify(nameof(CanUseConnection));
        Notify(nameof(ServiceVersionText)); Notify(nameof(ServiceVersionDisplay)); Notify(nameof(ServiceStateText)); Notify(nameof(ServiceStateTone));
        Notify(nameof(UpdateMessage)); Notify(nameof(UpdateCheckedAtText)); Notify(nameof(IsUpdateInProgress));
        Notify(nameof(EnvironmentEnabled)); Notify(nameof(EnvironmentBadgeText)); Notify(nameof(SelfCheckStatus)); Notify(nameof(SelfCheckTone));
        Notify(nameof(ConnectionDisabledReason)); Notify(nameof(PairingDisabledReason)); Notify(nameof(ClearPairingDisabledReason));
        Notify(nameof(RoutingIsGlobal)); Notify(nameof(RoutingIsApps));
        Notify(nameof(RoutingApps)); Notify(nameof(CanChangeRouting));
        if (selectedRoutingApp is not null && !RoutingApps.Contains(selectedRoutingApp)) selectedRoutingApp = null;
        Notify(nameof(SelectedRoutingApp));
        if (observedSelfCheckStatus != SelfCheckStatus)
        {
            observedSelfCheckStatus = SelfCheckStatus;
            if (CurrentPage == PageKind.Environment) _ = LoadSelfCheckAsync();
        }
        CommandManager.InvalidateRequerySuggested();
    }
    public Task ExportAuditAsync(string path) => RunAsync(async () =>
    {
        var response = await (client ?? throw new IOException()).SendAsync("read_audit", cancellationToken: lifetime.Token);
        if (!response.Ok)
        {
            Update(snapshot with { Message = response.Error ?? "诊断读取失败，请联系管理员。" }); return;
        }
        var selfCheck = await client.SendAsync("read_selfcheck", cancellationToken: lifetime.Token);
        if (!selfCheck.Ok)
        {
            Update(snapshot with { Message = selfCheck.Error ?? "诊断读取失败，请联系管理员。" }); return;
        }
        if (response.Audit is null && selfCheck.SelfCheck is null)
        {
            Update(snapshot with { Message = "尚无可导出的诊断记录,请完成一次连接后重试。" }); return;
        }
        // 验证两段都是 JSON，再原样嵌入，避免把对象变成转义字符串。
        using var auditJson = response.Audit is null ? null : JsonDocument.Parse(response.Audit);
        using var selfCheckJson = selfCheck.SelfCheck is null ? null : JsonDocument.Parse(selfCheck.SelfCheck);
        var diagnostics = "{\"firewall_audit\":" + (auditJson?.RootElement.GetRawText() ?? "null")
            + ",\"self_check\":" + (selfCheckJson?.RootElement.GetRawText() ?? "null") + "}";
        await File.WriteAllTextAsync(path, diagnostics, lifetime.Token);
        Update(snapshot with { Message = "已导出诊断(防火墙审计 + 环境自检)。" });
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
