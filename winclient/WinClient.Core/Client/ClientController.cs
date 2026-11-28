using System.Net;
using System.Net.Sockets;
using WinClient.Core.Auth;
using WinClient.Core.Pairing;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using WinClient.Core.State;
using WinClient.Core.Storage;
using WinClient.Core.EnvironmentSupport;

// 测试工程需要直接调用 SameSession，并用实现 IRenewableSessionSource 的假件驱动续期流程。
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("WinClient.Tests")]

namespace WinClient.Core.Client;

/// <summary>
/// 内部标记：实现此接口的会话来源与邀请码模式一样需要在连接期间续期。
/// 仅供测试假件使用，生产代码只有 AuthServerSessionSource 续期；不改 ISessionSource。
/// </summary>
internal interface IRenewableSessionSource : ISessionSource { }

public sealed record ClientSnapshot(ConnectionState State, string Status, string Message, bool ProtectionActive)
{
    public string Mode { get; init; } = "未配置";
    public string ExitStatus { get; init; } = "未检测";
    public string ExitIp { get; init; } = "";
    public string GuardStatus { get; init; } = "";
    public bool EnvironmentEnabled { get; init; } = true;
    public string EnvironmentStatus { get; init; } = "未应用";
    public string SelfCheckStatus { get; init; } = "未检测";
    public string RoutingMode { get; init; } = "global";
    public string[] RoutingApps { get; init; } = [];
}

/// <summary>Owns the serialized user flow, effects and session lifetime; no UI dependencies.</summary>
public sealed class ClientController : IDisposable
{
    internal static readonly TimeSpan BrowserWarningWindow = TimeSpan.FromMinutes(2);
    public const string BrowserWarningMarker = "再点一次「仍然继续」";
    internal Func<DateTimeOffset>? NowProvider { get; set; }
    private DateTimeOffset? browserWarnedAt;
    private IReadOnlyList<string>? browsersAtApply;
    internal static readonly TimeSpan ExitCheckDelay = TimeSpan.FromSeconds(3);
    internal static readonly TimeSpan ExitCheckRetry = TimeSpan.FromSeconds(5);
    internal const int ExitCheckAttempts = 5;
    internal const int UnverifiableHintRounds = 1;
    internal static readonly TimeSpan UnverifiableRecheckInterval = TimeSpan.FromMinutes(1);
    internal const string PairingUnverifiableHint = "连不到澳洲出口，现在可能上不了网。可以点「断开」恢复原来的网络；小主机换过地址的话，在小主机上重新导出配对文件再导入。";
    internal const string AuthUnverifiableHint = "连不到澳洲出口，现在可能上不了网。可以点「断开」恢复原来的网络，或联系管理员。";
    internal static readonly TimeSpan ExitRecheckInterval = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan TestBuildRecheckInterval = TimeSpan.FromMinutes(1);
    internal const int FirstConnectRetries = 3;
    // 首次连接失败自动恢复的两句提示与测试包自动断开的提示(原文固定,改动须同步文档与测试)。
    private const string AbandonRestored = "连接失败，已恢复原来的网络，当前没有走澳洲出口。";
    private const string AbandonNotRestored = "连接失败，原来的网络没能恢复：请点「断开」再试一次，还不行就重启电脑。";
    private const string TestBuildDisconnected = "测试包：出口核验不了，已自动断开并恢复原来的网络。";
    // 上次没断开但启动时找不到配对文件或登录凭据:保护保持,停在需人工处理,提示用户点断开。
    internal const string KeptWithoutPairingMessage = "上次的连接没有断开，但现在找不到配对文件。断网保护保持，电脑暂时上不了网。请点「断开」恢复原来的网络，重新导入配对文件后再连接。";
    internal const string KeptWithoutCredentialsMessage = "上次的连接没有断开，但现在找不到登录凭据。断网保护保持，电脑暂时上不了网。请点「断开」恢复原来的网络，重新兑换邀请码后再连接。";
    internal const string PatrolModeMismatchStatus = "代理范围与断网保护记录不一致，本轮没有检查防火墙规则";
    internal static readonly TimeSpan PatrolInterval = TimeSpan.FromSeconds(60);
    // 测试可同时记录所有用途；未注入时仍使用原有 delayAsync，不改变调度行为。
    internal Func<TimeSpan, CancellationToken, string, Task>? DelayWithPurposeAsync { get; set; }
    private readonly IExitProbe? exitProbe;
    private readonly IEnvironmentEnforcer? environment;
    private readonly IEnvironmentSettingsStore? environmentSettings;
    private readonly IIpv6Probe? ipv6Probe;
    private readonly IAdapterProbe? adapterProbe;
    private readonly IBrowserProcessProbe? browserProbe;
    private readonly IProxySettingsProbe? proxyProbe;
    private readonly Action<EnvironmentReport>? reportSink;
    private readonly IRoutingSettingsStore? routingSettings;
    private readonly string serviceProcessPath;
    private RoutingPolicy activeRouting = RoutingPolicy.Global;
    private readonly Func<string, AppScope> scopeResolver;
    private IReadOnlyList<AppScope> activeScopes = [];
    private string selfCheckStatus = "未检测";
    private bool environmentApplied;
    private string environmentStatus = "未应用";
    private string exitStatus = "未检测";
    private string exitIp = "";
    private int unverifiableRounds;
    private string? messageBeforeUnverifiableHint;
    private string guardStatus = "";
    private object? exitCycle;
    private bool patrolScheduled;
    private object? patrolCycle;
    // 巡检自己的取消源:只跟「断网保护在不在」走,不跟连接的 lifetime 和代数走。
    // FailAsync 取消 lifetime 之后连接停住,保护还在,巡检要照常跑。
    private CancellationTokenSource patrolLifetime = new();
    // 会话续期（邀请码模式）：有效期走到八成时续期；网络类失败每五分钟重试，直到到期前一分钟为止。
    internal const double RenewAtFraction = 0.8;
    internal static readonly TimeSpan RenewRetryInterval = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan RenewMinLead = TimeSpan.FromMinutes(1);
    private ISessionSource? sessionSource;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
    private readonly IKillSwitch firewall;
    private readonly ITunnelTransport tunnel;
    private readonly string program;
    private readonly AuthEndpoint? authEndpoint;
    private readonly DeviceInfo device;
    private readonly ConnectionStateMachine machine = new();
    private readonly SemaphoreSlim gate = new(1, 1);
    private CancellationTokenSource lifetime = new();
    private SessionResponse? session;
    private bool protection;
    private bool protectionVerified;
    private string? firewallWarning;
    private const string KeepTunnelWarning = "断网保护未能重新套用:系统防火墙已被关闭或被策略覆盖,隧道保持但失去断网兜底;请立即在 Windows 安全中心开启防火墙或联系管理员";
    private const string WfpKeepTunnelWarning = "断网保护未能重新套用:系统过滤层的过滤器未能建立,隧道保持,但缺少这道断网兜底;请联系管理员";
    public const string RouteKeepTunnelWarning = "兜底路由未能建立,隧道保持,但隧道中断时虚拟机与 WSL 的流量可能直连;请联系管理员。";
    private readonly INicGuard? nicGuard;
    private readonly IConnectionReaper? reaper;
    // 地址变化后等 2 秒再收紧:一次换网会连着来好几次通知,合成一次。
    internal static readonly TimeSpan NicSweepDelay = TimeSpan.FromSeconds(2);
    private readonly IAddressChangeSource? addressChanges;
    private int nicSweepQueued;
    private string? reapWarning;
    private string? nicRestoreWarning;
    private string? removeWarning;
    private bool disposed;
    private long generation;
    // 连接记录:记住上次写进记录的状态与巡检文字,只在变化时补一行。
    private ConnectionState journaledState = ConnectionState.Disconnected;
    private string journaledPatrol = "";
    private string message = "";
    // 首次尝试:从没套过保护也没有恢复记录的那次连接;到第一次 Connected 或断开、换来源时结束。
    private bool firstAttempt;
    private int firstBackoffs;
    public bool TestBuild { get; init; }
    public Action<string>? Journal { get; init; }
    /// <summary>首次尝试被放弃并恢复原网络后触发;订阅者抛的异常由控制器接住。</summary>
    public event Action? AttemptAbandoned;
    public ClientSnapshot Snapshot
    {
        get
        {
            var routing = protection || machine.State != ConnectionState.Disconnected ? activeRouting : routingSettings?.Read() ?? RoutingPolicy.Global;
            return new(machine.State, machine.StatusText, message, protection)
            { Mode = sessionSource?.Mode ?? "未配置", ExitStatus = exitStatus, ExitIp = exitIp, GuardStatus = guardStatus,
                EnvironmentEnabled = environmentSettings?.Read().Enabled ?? true, EnvironmentStatus = environmentStatus,
                SelfCheckStatus = selfCheckStatus, RoutingMode = ModeName(routing), RoutingApps = routing.Apps.ToArray() };
        }
    }
    private static string ModeName(RoutingPolicy policy) => policy.Mode == RoutingMode.Apps ? "apps" : "global";
    public event Action<ClientSnapshot>? Changed;

    public ClientController(AuthApiClient? auth, ICredentialStore credentials, IKillSwitch firewall,
        ITunnelTransport tunnel, string program, DeviceInfo device, AuthEndpoint? authEndpoint = null, IExitProbe? exitProbe = null,
        IEnvironmentEnforcer? environment = null, IEnvironmentSettingsStore? environmentSettings = null,
        IIpv6Probe? ipv6Probe = null, Action<EnvironmentReport>? reportSink = null,
        IRoutingSettingsStore? routingSettings = null, string? serviceProcessPath = null, IAdapterProbe? adapterProbe = null,
        IBrowserProcessProbe? browserProbe = null, INicGuard? nicGuard = null, IConnectionReaper? reaper = null,
        Func<string, AppScope>? scopeResolver = null, IProxySettingsProbe? proxyProbe = null,
        IAddressChangeSource? addressChanges = null)
        : this(auth is null ? null : new AuthServerSessionSource(auth, credentials), firewall, tunnel, program, device,
            authEndpoint: authEndpoint, exitProbe: exitProbe, environment: environment, environmentSettings: environmentSettings,
            ipv6Probe: ipv6Probe, reportSink: reportSink, routingSettings: routingSettings, serviceProcessPath: serviceProcessPath, adapterProbe: adapterProbe,
            browserProbe: browserProbe, nicGuard: nicGuard, reaper: reaper, scopeResolver: scopeResolver, proxyProbe: proxyProbe,
            addressChanges: addressChanges) { }

    public ClientController(ISessionSource? sessionSource, IKillSwitch firewall,
        ITunnelTransport tunnel, string program, DeviceInfo device, Func<TimeSpan, CancellationToken, Task>? delayAsync = null,
        AuthEndpoint? authEndpoint = null, IExitProbe? exitProbe = null,
        IEnvironmentEnforcer? environment = null, IEnvironmentSettingsStore? environmentSettings = null,
        IIpv6Probe? ipv6Probe = null, Action<EnvironmentReport>? reportSink = null,
        IRoutingSettingsStore? routingSettings = null, string? serviceProcessPath = null, IAdapterProbe? adapterProbe = null,
        IBrowserProcessProbe? browserProbe = null, INicGuard? nicGuard = null, IConnectionReaper? reaper = null,
        Func<string, AppScope>? scopeResolver = null, IProxySettingsProbe? proxyProbe = null,
        IAddressChangeSource? addressChanges = null)
    {
        this.scopeResolver = scopeResolver ?? AppScope.Exact;
        this.nicGuard = nicGuard;
        this.reaper = reaper;
        this.sessionSource = sessionSource;
        this.delayAsync = delayAsync ?? ((delay, token) => Task.Delay(delay, token));
        this.firewall = firewall;
        this.tunnel = tunnel;
        this.program = program;
        this.authEndpoint = authEndpoint;
        this.device = device;
        this.exitProbe = exitProbe;
        this.environment = environment;
        this.environmentSettings = environmentSettings;
        this.ipv6Probe = ipv6Probe;
        this.adapterProbe = adapterProbe;
        this.browserProbe = browserProbe;
        this.proxyProbe = proxyProbe;
        this.reportSink = reportSink;
        this.routingSettings = routingSettings;
        this.serviceProcessPath = serviceProcessPath ?? Environment.ProcessPath ?? "WinClient.App.exe";
        tunnel.TunnelDown += OnTunnelDown;
        this.addressChanges = addressChanges;
        if (addressChanges is not null) addressChanges.Changed += OnAddressChanged;
    }

    public async Task InitializeAsync(bool autoConnect = true, bool keepProtection = false)
    {
        const string protectionNotice = "后台服务已重新启动，断网保护保持，正在恢复连接。";
        var keptProtection = false;
        string? warning = null;
        await gate.WaitAsync();
        try
        {
            WriteJournal($"启动：保持保护={(keepProtection ? "是" : "否")}，自动连接={(autoConnect ? "是" : "否")}，" +
                $"恢复记录={PendingRecordText()}，模式={sessionSource?.Mode ?? "未配置"}");
            // 先判断「上次没断开且有恢复记录」时会话来源还能不能用:凭据读不出来也按找不到处理。
            var keptUsable = false;
            var keptMissing = false;
            if (keepProtection && firewall.HasPendingState)
            {
                if (sessionSource is PairingSessionSource) keptUsable = true;
                else if (sessionSource is AuthServerSessionSource authSource)
                {
                    try { keptUsable = authSource.HasCredentials; }
                    catch (Exception ex) when (IsOperational(ex)) { keptUsable = false; }
                    keptMissing = !keptUsable;
                }
                else if (sessionSource is null) keptMissing = true;
            }
            if (keptUsable)
            {
                protection = true;
                protectionVerified = true;
                message = protectionNotice;
                keptProtection = true;
                environmentApplied = environment?.HasPendingState ?? false;
                WriteJournal("启动：接回断网保护，随后自动连接");
                SyncPatrol();
            }
            else if (keptMissing)
            {
                // 上次没断开但现在找不到配对文件或登录凭据:保护保持,停在需人工处理,只等用户点断开。
                protection = true;
                environmentApplied = environment?.HasPendingState ?? false;
                // 这条路不经过 ConnectAsync:巡检要按上次套保护时的代理范围去查,在这里读一次;读不到就留默认,由巡检里的范围核对兜住。
                try
                {
                    activeRouting = routingSettings?.Read() ?? RoutingPolicy.Global;
                    activeScopes = activeRouting.Mode == RoutingMode.Apps ? activeRouting.Apps.Select(scopeResolver).ToArray() : [];
                }
                catch (Exception ex) when (IsOperational(ex)) { WriteJournal("启动：读不到代理范围设置：" + ConnectJournal.Describe(ex)); }
                await ExecuteAsync(machine.Handle(new(ConnectionEventKind.OperationFailed)));
                message = sessionSource is AuthServerSessionSource ? KeptWithoutCredentialsMessage : KeptWithoutPairingMessage;
                WriteJournal("启动：找不到配对文件或登录凭据，断网保护保持，停在需人工处理");
            }
            else
            {
                warning = await firewall.RecoverAsync();
                if (nicGuard is not null)
                {
                    var nicWarning = await nicGuard.RestoreAsync();
                    if (nicWarning is not null) warning = warning is null ? nicWarning : warning + " " + nicWarning;
                }
                if (warning is not null) message = warning + (sessionSource is null ? " 未配置服务器。" : "");
                else if (sessionSource is null) message = "未配置服务器";
                if (!await RestoreEnvironmentAsync())
                {
                    const string environmentWarning = "启动时未能恢复上次的时区或浏览器设置,请联系管理员。";
                    warning = warning is null ? environmentWarning : warning + " " + environmentWarning;
                    message += " " + environmentWarning;
                }
                WriteJournal($"启动：已做启动恢复，提醒={(warning is null ? "无" : "有")}");
            }
        }
        catch (Exception ex) when (IsOperational(ex))
        {
            await FailAsync(ex);
            message = "启动时未能恢复上次的断网保护设置，恢复记录已保留；请联系管理员处理后重新启动后台服务。";
        }
        finally { Publish(); gate.Release(); }
        if (keptProtection)
        {
            await ConnectAsync(fromUser: false);
            // 连接过程会更新消息；保留重启时的保护提示，不覆盖既有失败原因。
            if (!message.Contains("保持", StringComparison.Ordinal))
            {
                message = protectionNotice + " " + message;
                Publish();
            }
            return;
        }
        if (autoConnect && sessionSource is not null && machine.State != ConnectionState.NeedsManual)
        {
            try { if (sessionSource is PairingSessionSource || sessionSource is AuthServerSessionSource { HasCredentials: true }) await ConnectAsync(fromUser: false); }
            catch (Exception ex) when (IsOperational(ex)) { message = "无法读取本地登录凭据，请重新兑换邀请码。"; Publish(); }
        }
        // 自动连接会更新消息；保留降级提示，同时保留连接过程自身的结果。
        if (warning is not null && !message.Contains(warning, StringComparison.Ordinal))
        {
            message = warning + " " + message;
            Publish();
        }
    }

    public async Task RedeemAsync(string code)
    {
        await gate.WaitAsync();
        try
        {
            if (sessionSource is not AuthServerSessionSource auth)
            { message = sessionSource is PairingSessionSource ? "当前为自用模式；如需使用邀请码，请先清除配对文件。" : "未配置服务器"; return; }
            if (string.IsNullOrWhiteSpace(code)) { message = "请输入邀请码。"; return; }
            var response = await auth.RedeemAsync(code.Trim(), device);
            if (response.Result == AuthResult.Ok && response.Value is not null)
            {
                message = "兑换成功，请点击连接。";
            }
            else message = AuthMessage(response.Result);
        }
        catch (Exception ex) when (IsOperational(ex)) { message = "兑换未完成，请检查网络与本地凭据存储。"; }
        finally { Publish(); gate.Release(); }
    }

    internal static string BrowserRunningWarning(string action, IReadOnlyList<string> browsers) =>
        $"{string.Join(" 与 ", browsers)} 正在运行:{action}会切换系统时区与浏览器策略,已打开的网页会当场跳变。请先关闭浏览器再{action},或在两分钟内{BrowserWarningMarker}。";

    private bool ShouldWarnBrowsers(string action, bool checkApplied)
    {
        if (browserProbe is null || environment is null) return false;
        if (checkApplied ? !environmentApplied : !(environmentSettings?.Read() ?? EnvironmentSettingsStore.Default).ForNode(session?.Node).Enabled)
            return false;
        var now = NowProvider?.Invoke() ?? DateTimeOffset.UtcNow;
        if (browserWarnedAt.HasValue && now - browserWarnedAt.Value <= BrowserWarningWindow)
        {
            browserWarnedAt = null;
            return false;
        }
        IReadOnlyList<string>? running = null;
        try { running = browserProbe.RunningBrowsers(); }
        catch (Exception ex) when (IsOperational(ex)) { }
        if (running is null || running.Count == 0)
        {
            browserWarnedAt = null;
            return false;
        }
        browserWarnedAt = now;
        message = BrowserRunningWarning(action, running);
        return true;
    }

    public Task ConnectAsync() => ConnectAsync(fromUser: true);

    internal async Task ConnectAsync(bool fromUser)
    {
        await gate.WaitAsync();
        try
        {
            WriteJournal($"连接请求：来源={(fromUser ? "用户" : "自动")}，状态={ConnectJournal.StateName(machine.State)}，" +
                $"保护={(protection ? "有" : "无")}，恢复记录={PendingRecordText()}");
            if (sessionSource is null) { message = protection ? KeptWithoutPairingMessage : "未配置服务器"; WriteJournal("连接未开始：未配置服务器"); return; }
            if (machine.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting)
            { WriteJournal("连接未开始：已在连接或已连接"); return; }
            activeRouting = routingSettings?.Read() ?? RoutingPolicy.Global;
            if (activeRouting.Mode == RoutingMode.Apps && activeRouting.Apps.Count == 0)
            { message = "仅指定程序模式至少要选一个程序,请先添加程序或切回全部流量。"; WriteJournal("连接未开始：指定程序名单为空"); return; }
            activeScopes = activeRouting.Mode == RoutingMode.Apps ? activeRouting.Apps.Select(scopeResolver).ToArray() : [];
            if (firewall.HasPendingState && (firewall.PendingMode ?? "global") != ModeName(activeRouting))
            { message = "上次的断网保护记录与当前代理范围不一致,请先用原来的代理范围连接并正常断开,或重启后台服务后再试。"; WriteJournal("连接未开始：恢复记录与代理范围不一致"); return; }
            if (nicGuard is not null)
            {
                string? publicAdapter;
                try { publicAdapter = nicGuard.PublicIpv4Adapter(); }
                catch (Exception ex) when (IsOperational(ex))
                {
                    message = "无法读取网卡地址,已拒绝连接;请重试或联系管理员。";
                    WriteJournal("连接未开始：读不到网卡地址");
                    return;
                }
                if (publicAdapter is not null)
                {
                    message = $"网卡「{publicAdapter}」上直接有公网 IPv4 地址(通常是电脑自己拨号上网),部分软件和网页可以直接读到这个地址,已拒绝连接。请改由路由器拨号上网后再连接,或联系管理员。";
                    WriteJournal("连接未开始：网卡上有公网 IPv4");
                    return;
                }
            }
            if (fromUser && ShouldWarnBrowsers("连接", checkApplied: false))
            { WriteJournal("连接未开始：浏览器正在运行，等用户再点一次"); return; }
            firstAttempt = !protection && !firewall.HasPendingState;
            firstBackoffs = 0;
            WriteJournal($"开始连接：模式={sessionSource.Mode}，代理范围=" +
                $"{(activeRouting.Mode == RoutingMode.Apps ? $"仅指定程序 {activeRouting.Apps.Count} 个" : "全部流量")}" +
                $"，首次尝试={(firstAttempt ? "是" : "否")}");
            lifetime.Cancel();
            lifetime.Dispose();
            lifetime = new();
            Interlocked.Increment(ref generation);
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.UserConnect)));
            await FetchSessionAsync();
            await MaybeAbandonAfterLoginFailureAsync();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }
        catch (Exception ex) when (firstAttempt) { await FailAsync(ex); }
        finally
        {
            WriteJournal($"连接请求结束：状态={ConnectJournal.StateName(machine.State)}，保护={(protection ? "有" : "无")}");
            Publish();
            gate.Release();
        }
    }

    public async Task DisconnectAsync()
    {
        if (ShouldWarnBrowsers("断开", checkApplied: true))
        { WriteJournal("断开未开始：浏览器正在运行，等用户再点一次"); Publish(); return; }
        lifetime.Cancel();
        // 正在跑的巡检要立刻让路;断开没成功、保护还在时,状态迁移后的 SyncPatrol 会重新排上。
        patrolLifetime.Cancel();
        Interlocked.Increment(ref generation);
        await gate.WaitAsync();
        try
        {
            WriteJournal($"断开请求：状态={ConnectJournal.StateName(machine.State)}，保护={(protection ? "有" : "无")}");
            EndFirstAttempt();
            guardStatus = "";
            nicRestoreWarning = null;
            removeWarning = null;
            // Execution is ordered: a failure to stop the tunnel must not proceed to Remove.
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.UserDisconnect)));
            session = null;
            var environmentRestored = await RestoreEnvironmentAsync();
            if (removeWarning is not null)
                message = "已断开。" + removeWarning + (environmentRestored ? "" : " 时区或浏览器设置未能恢复，请联系管理员。");
            else
                message = environmentRestored ? "已断开，原网络设置已恢复。"
                    : "已断开,原网络设置已恢复;但时区或浏览器设置未能恢复,请联系管理员。";
            if (nicRestoreWarning is not null) message += " " + nicRestoreWarning;
            WriteJournal($"断开完成：环境恢复={(environmentRestored ? "成功" : "失败")}");
        }
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }
        finally { Publish(); gate.Release(); }
    }

    public async Task RefreshSessionAsync()
    {
        await gate.WaitAsync();
        try
        {
            if (machine.State is ConnectionState.Connected or ConnectionState.Reconnecting) await FetchSessionAsync();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }
        finally { Publish(); gate.Release(); }
    }

    public async Task SetRoutingAsync(string mode, IReadOnlyList<string> apps)
    {
        await gate.WaitAsync();
        try
        {
            if (protection || machine.State != ConnectionState.Disconnected)
            { message = "请先断开连接,再更改代理范围。"; return; }
            if (firewall.HasPendingState)
            { message = "断网保护的恢复记录尚在,请先连接并正常断开后再更改代理范围。"; return; }
            RoutingPolicy policy;
            try { policy = RoutingPolicy.Create(mode, apps); }
            catch (ArgumentException ex) { message = ex.Message; return; }
            if (routingSettings is null) { message = "代理范围设置不可用,请联系管理员。"; return; }
            routingSettings.Write(policy);
            message = policy.Mode == RoutingMode.Global ? "代理范围已更新:全部流量" : $"代理范围已更新:仅 {policy.Apps.Count} 个指定程序";
        }
        catch (Exception ex) when (IsOperational(ex)) { message = "代理范围保存失败,请联系管理员。"; }
        finally { Publish(); gate.Release(); }
    }

    public async Task ForceRestoreEnvironmentAsync()
    {
        await gate.WaitAsync();
        try
        {
            if (protection || machine.State != ConnectionState.Disconnected)
            { message = "请先断开连接,再强制恢复默认环境。"; return; }
            if (environment is null)
            { message = "环境一致性功能不可用。"; return; }
            var hadRecord = environment.HasPendingState;
            var policy = (environmentSettings?.Read() ?? EnvironmentSettingsStore.Default).ForNode(session?.Node);
            await environment.ForceRestoreAsync(policy.Target);
            environmentApplied = false;
            environmentStatus = policy.Enabled ? "未应用" : "未启用";
            message = hadRecord ? "已按恢复记录恢复原来的时区与浏览器设置。"
                : "没有恢复记录:已恢复自动时区并清除本产品写入的浏览器策略;系统时区未改动,如需请在 Windows 设置里调整。";
        }
        catch (Exception ex) when (ex is EnvironmentVerifyException || IsOperational(ex))
        {
            environmentStatus = "恢复失败,请联系管理员";
            message = "强制恢复未完成,请联系管理员。";
        }
        finally { Publish(); gate.Release(); }
    }

    public async Task SetEnvironmentEnabledAsync(bool enabled)
    {
        await gate.WaitAsync();
        try
        {
            environmentSettings?.WriteEnabled(enabled);
            if (environment is null) return;
            if (!enabled && environmentApplied)
            {
                if (!await RestoreEnvironmentAsync())
                    message = "时区与浏览器设置未能恢复,原值记录已保留,请联系管理员。";
                else environmentStatus = "未启用";
            }
            else if (enabled && machine.State == ConnectionState.Connected && !environmentApplied)
                await ApplyEnvironmentAsync();
            else environmentStatus = !enabled ? "未启用" : environmentApplied ? "已切换到澳洲时区与浏览器策略" : "未应用";
        }
        catch (Exception ex) when (IsOperational(ex))
        {
            // 环境总开关的保存失败也不触发连接失败处理。
            environmentStatus = "设置失败,请联系管理员;连接与断网保护不受影响";
        }
        finally { Publish(); gate.Release(); }
    }

    private async Task ApplyEnvironmentAsync()
    {
        if (environment is null) return;
        try
        {
            var policy = (environmentSettings?.Read() ?? EnvironmentSettingsStore.Default).ForNode(session?.Node);
            if (!policy.Enabled) { environmentStatus = "未启用"; return; }
            if (machine.State != ConnectionState.Connected || environmentApplied) return;
            browsersAtApply = null;
            try { browsersAtApply = browserProbe?.RunningBrowsers(); }
            catch (Exception ex) when (IsOperational(ex)) { }
            await environment.ApplyAsync(policy.Target);
            environmentApplied = true;
            environmentStatus = "已切换到澳洲时区与浏览器策略";
        }
        catch (Exception ex) when (ex is EnvironmentVerifyException || IsOperational(ex))
        {
            // 不能让环境项异常进入外层隧道故障处理，也不覆盖连接消息。
            environmentStatus = "设置失败,请联系管理员;连接与断网保护不受影响";
        }
    }

    private async Task<bool> RestoreEnvironmentAsync()
    {
        if (environment is null) return true;
        try
        {
            if (environmentApplied || environment.HasPendingState)
            {
                await environment.RestoreAsync();
                environmentApplied = false;
                browsersAtApply = null;
            }
            environmentStatus = (environmentSettings?.Read().Enabled ?? true) ? "未应用" : "未启用";
            return true;
        }
        catch (Exception ex) when (IsOperational(ex))
        {
            environmentStatus = "恢复失败,请联系管理员";
            return false;
        }
    }

    private async Task FetchSessionAsync()
    {
        var response = await sessionSource!.GetSessionAsync(lifetime.Token);
        lifetime.Token.ThrowIfCancellationRequested();
        WriteJournal("取会话：" + response.Result);
        if (response.Result != AuthResult.Ok || response.Value is null)
        { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.AuthRejected, response.Result))); return; }
        var next = response.Value;
        if (next.SessionExpiresAt <= DateTimeOffset.UtcNow || next.AccountExpiresAt <= DateTimeOffset.UtcNow)
        {
            WriteJournal("取会话：会话或账号已到期");
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired)));
            return;
        }
        await ApplySessionAsync(next);
    }

    /// <summary>套用已通过到期校验的会话：取会话与续期共用。</summary>
    private async Task ApplySessionAsync(SessionResponse next)
    {
        var nextIps = NodeIps(next);
        _ = TunnelTransport.RenderConfiguration(RenderedConfiguration(next)); // 安装规则前校验渲染后的配置。
        var previous = session;
        session = next;
        if (environmentApplied)
        {
            try
            {
                var policy = environmentSettings?.Read() ?? EnvironmentSettingsStore.Default;
                if (policy.ForNode(previous?.Node).Target.TimeZoneId != policy.ForNode(next.Node).Target.TimeZoneId &&
                    await RestoreEnvironmentAsync())
                    await ApplyEnvironmentAsync();
            }
            catch (Exception ex) when (ex is EnvironmentVerifyException || IsOperational(ex))
            {
                // 环境配置读取与重套用失败不进入隧道故障分路，也不覆盖连接消息。
                environmentStatus = "设置失败,请联系管理员;连接与断网保护不受影响";
            }
        }
        if (protection && previous is not null && machine.HasSession && SameSession(previous, next))
        {
            // 内容没变（只换了令牌与到期时间）：只换会话并重新安排定时器，不重启隧道。
        }
        else if (protection && previous is not null)
        {
            if (!NodeIps(previous).SequenceEqual(nextIps) || previous.Node.Hy2Port != next.Node.Hy2Port || previous.Node.RealityPort != next.Node.RealityPort)
                await ExecuteAsync(machine.Handle(new(ConnectionEventKind.NodeChanged, OldIps: NodeIps(previous), NewIps: nextIps)));
            // Refresh can change credentials as well as addresses: restart under the existing protection.
            await ExecuteAsync(machine.Handle(new(machine.HasSession ? ConnectionEventKind.TunnelDown : ConnectionEventKind.SessionOk)));
        }
        else await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionOk)));
        ScheduleExpiry(next);
        ScheduleRenewal(next);
    }

    /// <summary>
    /// 邀请码模式在会话有效期走到八成时安排续期；自用模式会话固定远期，不续期。
    /// 剩余不足一分钟时交给既有到期定时器。旧回调由 Schedule 的代数与 lifetime 取消自然作废。
    /// </summary>
    private void ScheduleRenewal(SessionResponse value)
    {
        if (sessionSource is not (AuthServerSessionSource or IRenewableSessionSource)) return;
        var remaining = Expiry(value) - DateTimeOffset.UtcNow;
        if (remaining <= RenewMinLead) return;
        Schedule(remaining * RenewAtFraction, () => RenewAsync(value), "续期");
    }

    /// <summary>
    /// 在串行锁内续期：内容不变只换会话；内容变了按既有刷新路径在保护下重启；
    /// 凭据类拒绝按既有规则进入需重新登录或需人工处理；网络类失败每五分钟重试直到到期前一分钟。
    /// </summary>
    private async Task RenewAsync(SessionResponse value)
    {
        if (!ReferenceEquals(value, session) || machine.State is not (ConnectionState.Connected or ConnectionState.Reconnecting)) return;
        var response = await sessionSource!.GetSessionAsync(lifetime.Token);
        lifetime.Token.ThrowIfCancellationRequested();
        WriteJournal("续期：" + response.Result);
        if (response.Result == AuthResult.Ok && response.Value is not null)
        {
            var next = response.Value;
            if (next.SessionExpiresAt <= DateTimeOffset.UtcNow || next.AccountExpiresAt <= DateTimeOffset.UtcNow)
            { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired))); return; }
            // 同内容会话也经过环境策略更新；是否重启隧道仍由既有比较集合决定。
            await ApplySessionAsync(next);
            return;
        }
        if (response.Result is AuthResult.InvalidToken or AuthResult.Expired or AuthResult.InviteNotFound
            or AuthResult.Disabled or AuthResult.Revoked or AuthResult.DeviceLimit)
        { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.AuthRejected, response.Result))); return; }
        // 网络、限速、异常响应、参数错误（以及成功却没有内容的异常响应）：隧道与状态不动，稍后再试。
        var remaining = Expiry(value) - DateTimeOffset.UtcNow;
        if (remaining > RenewMinLead)
        {
            var wait = remaining - RenewMinLead;
            Schedule(wait < RenewRetryInterval ? wait : RenewRetryInterval, () => RenewAsync(value), "续期");
        }
    }

    /// <summary>两份会话的节点与内核配置是否完全一致；不比较令牌与到期时间。</summary>
    internal static bool SameSession(SessionResponse a, SessionResponse b)
    {
        var x = a.Node;
        var y = b.Node;
        return x.Host == y.Host && x.RealityPort == y.RealityPort && x.Hy2Port == y.Hy2Port &&
            x.Sni == y.Sni && x.RealityPublicKey == y.RealityPublicKey && x.ShortId == y.ShortId &&
            x.Uuid == y.Uuid && x.Hy2Password == y.Hy2Password && x.Hy2ServerName == y.Hy2ServerName &&
            x.Hy2ObfsPassword == y.Hy2ObfsPassword &&
            (x.Hy2Certificate ?? []).SequenceEqual(y.Hy2Certificate ?? [], StringComparer.Ordinal);
    }

    private System.Text.Json.JsonElement RenderedConfiguration(SessionResponse value) =>
        RoutingRenderer.Render(LocalConfigRenderer.Render(value.Node), activeRouting, serviceProcessPath,
            sessionSource is AuthServerSessionSource ? authEndpoint : null, ScopePatterns());

    private string[]? ScopePatterns() => activeRouting.Mode == RoutingMode.Apps ? activeScopes.Select(scope => scope.Pattern).ToArray() : null;

    /// <summary>全部名单项连带范围内的程序文件并集(不分大小写去重),给过滤层与连接清理使用。</summary>
    private string[] ScopeExecutables() => activeScopes.SelectMany(scope => scope.Executables).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private Task ApplyAppsAsync() => firewall.ApplyAppsAsync(activeRouting.Apps, ScopeExecutables());

    private static DateTimeOffset Expiry(SessionResponse value) =>
        value.SessionExpiresAt < value.AccountExpiresAt ? value.SessionExpiresAt : value.AccountExpiresAt;

    private async Task ExecuteAsync(Transition transition)
    {
        try { await ExecuteEffectsAsync(transition); }
        finally
        {
            JournalState();
            UpdateMonitoring();
            // 状态第一次到 Connected 即视为首次尝试结束,之后的掉线重连按既有规则处理。
            if (machine.State == ConnectionState.Connected) EndFirstAttempt();
        }
    }

    private async Task ExecuteEffectsAsync(Transition transition)
    {
        JournalState();
        Publish();
        foreach (var effect in transition.Effects)
        {
            if (effect.Kind == EffectKind.ShowMessage)
            {
                message = sessionSource is PairingSessionSource && transition.State == ConnectionState.NeedsManual && machine.HasSession
                    ? "连不上澳洲出口，出口地址可能已变，请在小主机上重新导出配对文件再导入。断网保护仍保持。"
                    : effect.Message ?? "";
                continue;
            }
            var action = ConnectJournal.EffectName(effect);
            WriteJournal("动作开始：" + action);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                switch (effect.Kind)
                {
                    case EffectKind.ApplyKillSwitch:
                        var held = protectionVerified;
                        protection = true; // Even partial Apply must be treated as requiring explicit recovery.
                        var firewallApplied = false;
                        try
                        {
                            if (activeRouting.Mode == RoutingMode.Apps) await ApplyAppsAsync();
                            else await firewall.ApplyAsync(NodeIps(session!), program, session!.Node.Hy2Port, session.Node.RealityPort,
                                    sessionSource is AuthServerSessionSource ? authEndpoint : null);
                            protectionVerified = true;
                            firewallWarning = null;
                            reapWarning = null;
                            firewallApplied = true;
                        }
                        catch (FirewallIneffectiveException ex) when (held)
                        {
                            WriteJournal("套用断网保护没成功，隧道保持：" + ConnectJournal.Describe(ex));
                            var keep = ex is WfpUnavailableException ? WfpKeepTunnelWarning
                                : ex is RouteGuardUnavailableException ? RouteKeepTunnelWarning : KeepTunnelWarning;
                            firewallWarning = keep;
                            guardStatus = keep;
                            message = keep;
                        }
                        // 网卡收紧和防火墙那步分开做:防火墙没套成、隧道保持时,带公网 IPv6 的网卡也要关。
                        try
                        {
                            if (nicGuard is not null) await nicGuard.ApplyAsync(lifetime.Token);
                            if (firewallApplied) ReapStaleConnections();
                        }
                        catch (NicGuardException ex) when (held)
                        {
                            WriteJournal("套用断网保护没成功，隧道保持：" + ConnectJournal.Describe(ex));
                            var keep = NicKeepTunnelWarning(ex);
                            firewallWarning = firewallWarning is null ? keep : firewallWarning + " " + keep;
                            guardStatus = firewallWarning;
                            message = firewallWarning;
                        }
                        break;
                    case EffectKind.UpdateKillSwitchNode:
                        if (activeRouting.Mode != RoutingMode.Apps)
                            await firewall.UpdateNodeAsync(effect.NewIps!, program, session!.Node.Hy2Port, session.Node.RealityPort);
                        break;
                    case EffectKind.RemoveKillSwitch:
                        await firewall.RemoveAsync(); removeWarning = firewall.LastRemoveWarning;
                        if (removeWarning is not null)
                            WriteJournal("撤销断网保护：没有恢复记录，默认出站已按 Windows 默认改回允许");
                        protection = false; protectionVerified = false; firewallWarning = null; reapWarning = null;
                        if (nicGuard is not null) nicRestoreWarning = await nicGuard.RestoreAsync(); // 恢复失败不抛、不阻止状态迁移。
                        break;
                    case EffectKind.StopTunnel: tunnel.Stop(); break;
                    case EffectKind.StartTunnel:
                        if (session is null || session.SessionExpiresAt <= DateTimeOffset.UtcNow || session.AccountExpiresAt <= DateTimeOffset.UtcNow)
                        { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired))); break; }
                        try
                        {
                            await tunnel.StartAsync(RenderedConfiguration(session), lifetime.Token);
                            lifetime.Token.ThrowIfCancellationRequested();
                            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelUp)));
                            message = (firewallWarning ?? "虚拟网卡已就绪。") + (reapWarning is null ? "" : " " + reapWarning);
                            await ApplyEnvironmentAsync();
                        }
                        catch (FileNotFoundException ex)
                        {
                            WriteJournal("启动隧道没成功：" + ConnectJournal.Describe(ex));
                            // 首次尝试由放弃并恢复统一给提示;只有已持有保护的路径保留这句原文。
                            var wasFirstAttempt = firstAttempt;
                            await FailAsync(ex);
                            if (!wasFirstAttempt) message = "未找到连接内核，请联系管理员配置 sing-box.exe 路径。";
                        }
                        catch (InvalidDataException ex)
                        {
                            WriteJournal("启动隧道没成功：" + ConnectJournal.Describe(ex));
                            throw;
                        }
                        catch (Exception ex) when (ex is IOException or TimeoutException)
                        {
                            WriteJournal("启动隧道没成功：" + ConnectJournal.Describe(ex));
                            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelDown)));
                        }
                        break;
                    case EffectKind.ScheduleBackoff:
                        if (firstAttempt && firstBackoffs >= FirstConnectRetries)
                        {
                            // 首次尝试前三次退避(2、4、8 秒)照常;第 4 次要安排时放弃并恢复原网络。
                            await AbandonAsync(null, phrase: "连续 4 次没连上", reason: "原因：连续 4 次都没连上澳洲出口。");
                            break;
                        }
                        if (firstAttempt) firstBackoffs++;
                        Schedule(effect.Delay!.Value, async () =>
                        {
                            var next = machine.Handle(new(ConnectionEventKind.BackoffElapsed));
                            await ExecuteAsync(next);
                            if (machine.State == ConnectionState.Reconnecting && !next.Effects.Any(e => e.Kind == EffectKind.StartTunnel))
                                await FetchSessionAsync();
                        }, "退避");
                        break;
                }
                watch.Stop();
                WriteJournal($"动作结束：{action}，用时 {watch.ElapsedMilliseconds} 毫秒");
            }
            catch (Exception ex)
            {
                watch.Stop();
                WriteJournal($"动作出错：{action}，用时 {watch.ElapsedMilliseconds} 毫秒，{ConnectJournal.Describe(ex)}");
                throw;
            }
        }
    }

    /// <summary>测试包出口复核间隔为 1 分钟;正式包无法核验期间也是 1 分钟,其余 5 分钟。</summary>
    private TimeSpan RecheckInterval => TestBuild ? TestBuildRecheckInterval
        : unverifiableRounds > 0 ? UnverifiableRecheckInterval : ExitRecheckInterval;

    /// <summary>在迁移处理完成后统一更新监测；所有回调沿用串行锁、代数与生命周期。</summary>
    private void UpdateMonitoring()
    {
        if (machine.State != ConnectionState.Connected)
        {
            selfCheckStatus = "未检测";
            exitStatus = "未检测";
            exitIp = "";
            unverifiableRounds = 0;
            messageBeforeUnverifiableHint = null;
            if (activeRouting.Mode != RoutingMode.Apps || machine.State != ConnectionState.Reconnecting) exitCycle = null;
        }
        else if (session is not null && exitProbe is not null && exitCycle is null)
        {
            exitCycle = new object();
            exitStatus = "核验中";
            ScheduleExitCheck(ExitCheckDelay, exitCycle, 1);
        }
        SyncPatrol();
    }

    /// <summary>巡检只看断网保护在不在,和连接状态无关。</summary>
    private bool ShouldPatrol => protection;

    /// <summary>巡检只在已连接或重连中才改提示语;停住时那句处理指引不能被巡检的话盖掉,巡检结果只写进保护状态。</summary>
    private bool PatrolMaySpeak => machine.State is ConnectionState.Connected or ConnectionState.Reconnecting;

    /// <summary>保护是按哪种代理范围套上的,以恢复记录为准;和控制器手里的范围对不上时,防火墙巡检会按错的范围去收紧系统设置,整段不做。</summary>
    private bool PatrolModeMismatch => firewall.HasPendingState && (firewall.PendingMode ?? "global") != ModeName(activeRouting);

    /// <summary>让巡检定时和「保护在不在」对齐:保护没了或巡检被取消过,就丢掉旧定时;保护在而没有定时,就排一个。只在串行锁内调用。</summary>
    private void SyncPatrol()
    {
        if (patrolLifetime.IsCancellationRequested || (!ShouldPatrol && patrolScheduled))
        {
            // 旧取消源只取消、不释放:迟到的定时任务拿旧令牌等锁时不会撞上已释放的对象。
            patrolLifetime.Cancel();
            patrolLifetime = new();
            patrolScheduled = false;
            patrolCycle = null;
        }
        if (ShouldPatrol && !patrolScheduled && !disposed)
        {
            patrolCycle = new object();
            SchedulePatrol(patrolCycle);
        }
    }

    private void ScheduleExitCheck(TimeSpan wait, object cycle, int attempt)
        => Schedule(wait, () => CheckExitAsync(cycle, attempt), "出口核验");

    private async Task CheckExitAsync(object cycle, int attempt)
    {
        // 同一生命周期内也可能先断线后重连；连接轮次防止旧探测重复续排。
        if (!ReferenceEquals(cycle, exitCycle) || session is null) return;
        if (machine.State != ConnectionState.Connected)
        {
            if (activeRouting.Mode == RoutingMode.Apps) ScheduleExitCheck(RecheckInterval, cycle, 1);
            return;
        }
        exitStatus = "核验中";
        Publish();
        ExitProbeResult? exit;
        try { exit = await exitProbe!.ProbeDetailedAsync(lifetime.Token); }
        catch (Exception ex) when (IsOperational(ex) || ex is HttpRequestException) { exit = null; }
        if (lifetime.IsCancellationRequested || disposed) return;
        var address = exit?.Address;
        if (address is not null)
        {
            unverifiableRounds = 0;
            if (message == PairingUnverifiableHint || message == AuthUnverifiableHint)
                message = string.IsNullOrEmpty(messageBeforeUnverifiableHint) ? "虚拟网卡已就绪。" : messageBeforeUnverifiableHint;
            messageBeforeUnverifiableHint = null;
            exitIp = address.ToString();
            var matches = IPAddress.TryParse(session.Node.Host, out var expected) && address.Equals(expected);
            exitStatus = matches ? "已核验" : "不一致";
            WriteJournal(matches ? "出口核验：已核验" : "出口核验：不一致");
            if (activeRouting.Mode == RoutingMode.Apps) exitStatus += "(后台服务出口)";
            if (!matches) message = "出口地址与澳洲节点不一致,请联系管理员;断网保护保持,未自动断开。";
        }
        else if (attempt < ExitCheckAttempts)
        {
            WriteJournal($"出口核验：第 {attempt} 次没有回应");
            ScheduleExitCheck(ExitCheckRetry, cycle, attempt + 1);
            return;
        }
        else
        {
            exitStatus = "无法核验";
            exitIp = "";
            unverifiableRounds++;
            WriteJournal($"出口核验：无法核验，已连续 {unverifiableRounds} 轮");
            if (TestBuild && machine.State == ConnectionState.Connected)
            {
                // 测试包的第二道保险:一轮核验以「无法核验」收场就自动断开并恢复原网络,不再排下一次。
                await AbandonAsync(null, phrase: "测试包出口核验不了", reason: "原因：出口核验不了。", fixedMessage: TestBuildDisconnected);
                return;
            }
            if (unverifiableRounds >= UnverifiableHintRounds && machine.State == ConnectionState.Connected &&
                message != PairingUnverifiableHint && message != AuthUnverifiableHint)
            {
                messageBeforeUnverifiableHint = message;
                message = sessionSource is PairingSessionSource ? PairingUnverifiableHint : AuthUnverifiableHint;
            }
        }
        await CheckEnvironmentAsync(exit);
        if (!lifetime.IsCancellationRequested && !disposed) ScheduleExitCheck(RecheckInterval, cycle, 1);
    }

    private async Task CheckEnvironmentAsync(ExitProbeResult? exit)
    {
        selfCheckStatus = "检测中";
        Publish();
        var policy = (environmentSettings?.Read() ?? EnvironmentSettingsStore.Default).ForNode(session?.Node);
        EnvironmentInspection? inspection = null;
        if (policy.Enabled && environment is not null)
        {
            try { inspection = await environment.InspectAsync(lifetime.Token); }
            catch (Exception ex) when (IsOperational(ex)) { }
        }
        if (lifetime.IsCancellationRequested || disposed) return;
        bool? ipv6 = null;
        try { if (activeRouting.Mode != RoutingMode.Apps && ipv6Probe is not null) ipv6 = await ipv6Probe.CanReachAsync(lifetime.Token); }
        catch (Exception) { } // 探测异常仅代表本项无法核验，不进入连接失败路径。
        if (lifetime.IsCancellationRequested || disposed) return;
        IReadOnlyList<AdapterInfo>? adapters = null;
        try { adapters = adapterProbe?.Snapshot(); }
        catch (Exception ex) when (IsOperational(ex)) { }
        IReadOnlyList<string>? proxyFindings = null;
        try { proxyFindings = proxyProbe?.Snapshot(); }
        catch (Exception ex) when (IsOperational(ex)) { }
        var report = EnvironmentSelfCheck.Evaluate(new(exit, session!.Node.Host, policy.ExpectedCountry,
            policy.Enabled, environmentApplied, policy.Target, inspection, ipv6,
            RenderedConfiguration(session),
            DateTimeOffset.UtcNow) { Routing = activeRouting, AppPatterns = ScopePatterns(),
                Auth = sessionSource is AuthServerSessionSource ? authEndpoint : null, ServiceProcessPath = serviceProcessPath, Adapters = adapters,
                BrowsersAtApply = browsersAtApply, ProxyFindings = proxyFindings });
        selfCheckStatus = report.Summary;
        try { reportSink?.Invoke(report); }
        catch (Exception ex) when (IsOperational(ex)) { } // 写报告失败不影响已完成的检查与连接。
    }

    private void SchedulePatrol(object cycle)
    {
        patrolScheduled = true;
        _ = RunPatrolAsync(cycle, patrolLifetime.Token);
    }

    /// <summary>等 60 秒后在串行锁内跑一轮巡检。不走 Schedule:那条路绑着连接的 lifetime 和代数,连接停住后就排不上了。</summary>
    private async Task RunPatrolAsync(object cycle, CancellationToken token)
    {
        try
        {
            await DelayForPurposeAsync(PatrolInterval, token, "巡检");
            await gate.WaitAsync(token);
            try { if (!disposed) await PatrolAsync(cycle); }
            finally { Publish(); gate.Release(); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }

    private async Task PatrolAsync(object cycle)
    {
        if (!ReferenceEquals(cycle, patrolCycle)) return;
        if (!ShouldPatrol) { SyncPatrol(); return; }
        try
        {
            if (PatrolModeMismatch) { guardStatus = PatrolModeMismatchStatus; return; }
            var addedNote = await PatrolNewExecutablesAsync();
            var report = activeRouting.Mode == RoutingMode.Apps
                ? await firewall.PatrolAsync(KillSwitchPlanner.AppRuleNames(activeRouting.Apps.Count), enforceDefaultBlock: false, patrolLifetime.Token)
                : await firewall.PatrolAsync(KillSwitchPlanner.ExpectedRuleNames(sessionSource is AuthServerSessionSource), enforceDefaultBlock: true, patrolLifetime.Token);
            if (patrolLifetime.IsCancellationRequested || disposed) return;
            if (report.MissingRules.Count > 0)
            {
                if (session is not null)
                {
                    if (activeRouting.Mode == RoutingMode.Apps) await ApplyAppsAsync();
                    else await firewall.ApplyAsync(NodeIps(session), program, session.Node.Hy2Port, session.Node.RealityPort,
                            sessionSource is AuthServerSessionSource ? authEndpoint : null);
                    guardStatus = $"已重建 {report.MissingRules.Count} 条本项目规则";
                }
                else guardStatus = "巡检失败,下一轮重试";
            }
            else if (!report.Clean) guardStatus = $"已重新收紧 {report.Reenforced.Count + report.NewlyDisabled.Count} 条规则";
            else guardStatus = addedNote ?? "正常";
            if (firewallWarning is not null)
            {
                firewallWarning = null;
                protectionVerified = true;
                if (PatrolMaySpeak) message = "断网保护已重新生效。";
            }
        }
        catch (FirewallIneffectiveException ex) when (ex is WfpUnavailableException or RouteGuardUnavailableException)
        { guardStatus = ex.Message; if (PatrolMaySpeak) message = guardStatus; }
        catch (FirewallIneffectiveException)
        {
            guardStatus = "系统防火墙已被关闭或被策略覆盖,断网保护可能失效,请立即在 Windows 安全中心开启防火墙或联系管理员";
            if (PatrolMaySpeak) message = guardStatus;
        }
        catch (Exception ex) when (IsOperational(ex)) { guardStatus = "巡检失败,下一轮重试"; }
        finally
        {
            await PatrolNicAsync(); // 防火墙巡检(含规则重建分路)之后再巡检网卡。
            JournalPatrol();
            Publish();
            if (!disposed && !patrolLifetime.IsCancellationRequested && ShouldPatrol && ReferenceEquals(cycle, patrolCycle)) SchedulePatrol(cycle);
        }
    }

    /// <summary>
    /// 仅指定程序模式:重新枚举连带范围内的程序文件,有新增就重新套用过滤层;匹配式保持连接时的值,不重启隧道。
    /// 只增不减(旧文件仍保留保护);套用成功后才更新记录,失败则下一轮重试。返回提示文字,没有新增返回空。
    /// </summary>
    private async Task<string?> PatrolNewExecutablesAsync()
    {
        if (activeRouting.Mode != RoutingMode.Apps || activeScopes.Count == 0) return null;
        var known = ScopeExecutables().ToHashSet(StringComparer.OrdinalIgnoreCase);
        var fresh = activeScopes.Select(scope => !scope.Expanded ? scope : scope with
        {
            Executables = scope.Executables.Concat(scopeResolver(scope.Selected).Executables)
                .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray()
        }).ToArray();
        var union = fresh.SelectMany(scope => scope.Executables).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var added = union.Count(path => !known.Contains(path));
        if (added == 0) return null;
        await firewall.ApplyAppsAsync(activeRouting.Apps, union);
        activeScopes = fresh;
        return $"已为新出现的 {added} 个程序文件补上保护";
    }

    internal static string PublicIpv4ParkedMessage(string adapter, bool apps) =>
        $"网卡「{adapter}」上出现了公网 IPv4 地址(通常是电脑自己拨号上网,或换了网络),部分软件和网页可以直接读到这个地址,已停止连接。断网保护保持,{(apps ? "名单里的程序" : "电脑")}暂时上不了网。请点「断开」恢复原来的网络,改由路由器拨号上网后再连接,或联系管理员。";
    internal static string PublicIpv4GuardStatus(string adapter) => $"网卡「{adapter}」出现公网 IPv4 地址,连接已停止,断网保护保持";

    /// <summary>巡检里的网卡收紧。</summary>
    private Task PatrolNicAsync() => TightenNicAsync(fromPatrol: true);

    /// <summary>
    /// 读一次网卡:新出现公网 IPv6 的先记后关;出现公网 IPv4 时,隧道可能在跑就停掉、保护保持。
    /// 巡检和地址变化通知共用;只在串行锁内调用。
    /// </summary>
    private async Task TightenNicAsync(bool fromPatrol)
    {
        if (nicGuard is null || patrolLifetime.IsCancellationRequested || disposed) return;
        string? publicIpv4 = null;
        try
        {
            var nic = await nicGuard.PatrolAsync(patrolLifetime.Token);
            if (nic.NewlyDisabled.Count > 0)
            {
                var closed = $"已关闭新出现公网 IPv6 的网卡 {nic.NewlyDisabled.Count} 个";
                guardStatus = fromPatrol && guardStatus.Length > 0 ? guardStatus + "," + closed : closed;
            }
            if (nic.PublicIpv4Adapters.Count > 0) publicIpv4 = nic.PublicIpv4Adapters[0];
        }
        catch (NicGuardException ex) { guardStatus = ex.Message; if (PatrolMaySpeak) message = guardStatus; }
        catch (Exception ex) when (IsOperational(ex)) { }
        if (publicIpv4 is not null) await ParkForPublicIpv4Async(publicIpv4);
    }

    /// <summary>网卡上出现公网 IPv4:和连接前拒连同一个口径。隧道可能在跑就停掉,保护保持;已经停住的只更新巡检状态。</summary>
    private async Task ParkForPublicIpv4Async(string adapter)
    {
        if (machine.State is not (ConnectionState.Connecting or ConnectionState.Connected or ConnectionState.Reconnecting))
        {
            guardStatus = PublicIpv4GuardStatus(adapter);
            return;
        }
        if (firstAttempt)
        {
            // 从没连上的那次尝试:照既有口径放弃并恢复原来的网络。
            await AbandonAsync(null, phrase: "网卡出现公网 IPv4", reason: $"原因：网卡「{adapter}」上出现了公网 IPv4 地址。");
            return;
        }
        WriteJournal("网卡出现公网 IPv4：停止隧道，断网保护保持");
        lifetime.Cancel();
        try
        {
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.OperationFailed)));
            message = PublicIpv4ParkedMessage(adapter, activeRouting.Mode == RoutingMode.Apps);
        }
        catch (Exception ex) when (IsOperational(ex)) { message = "连接内核未能停止，请联系管理员；断网保护保留。"; }
        guardStatus = PublicIpv4GuardStatus(adapter);
    }

    /// <summary>系统线程上的回调:只排一次网卡收紧,不读网卡、不拿锁。</summary>
    private void OnAddressChanged()
    {
        if (disposed || !protection || nicGuard is null) return;
        if (Interlocked.Exchange(ref nicSweepQueued, 1) == 1) return;
        _ = RunNicSweepAsync(patrolLifetime.Token);
    }

    /// <summary>等 2 秒后在串行锁内做一次网卡收紧。用巡检的取消口:断开时让路,保护撤掉就作废。</summary>
    private async Task RunNicSweepAsync(CancellationToken token)
    {
        var entered = false;
        try
        {
            await DelayForPurposeAsync(NicSweepDelay, token, "网卡收紧");
            await gate.WaitAsync(token);
            entered = true;
            try
            {
                // 进锁就把排队标记放掉:收紧期间再来的通知要能再排一次。
                Interlocked.Exchange(ref nicSweepQueued, 0);
                if (disposed || !protection) return;
                await TightenNicAsync(fromPatrol: false);
                JournalPatrol();
            }
            finally { Publish(); gate.Release(); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally { if (!entered) Interlocked.Exchange(ref nicSweepQueued, 0); }
    }

    private static string NicKeepTunnelWarning(NicGuardException ex) =>
        $"未能关闭网卡「{ex.AdapterName ?? "未知"}」的 IPv6,隧道保持,但该网卡的公网 IPv6 地址可能被网页读到;请联系管理员。";

    /// <summary>断网保护套用后重置连接前建立的隧道外 TCP 连接;失败只提示,不影响连接。</summary>
    private void ReapStaleConnections()
    {
        if (reaper is null) return;
        try
        {
            var report = reaper.Reap(new ReapPolicy(activeRouting.Mode == RoutingMode.Apps,
                activeRouting.Mode == RoutingMode.Apps ? ScopeExecutables() : activeRouting.Apps, program,
                NodeIps(session!), sessionSource is AuthServerSessionSource ? authEndpoint : null));
            if (report.Failed + report.Remaining > 0)
                reapWarning = $"有 {Math.Max(report.Failed, report.Remaining)} 条连接前建立的连接未能重置,相关软件可能仍走原网络,请重启这些软件。";
        }
        catch (Exception ex) when (IsOperational(ex)) { }
    }

    private void ScheduleExpiry(SessionResponse value)
    {
        Schedule(Expiry(value) - DateTimeOffset.UtcNow, async () =>
        {
            if (ReferenceEquals(value, session)) await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired)));
        }, "到期");
    }
    private void Schedule(TimeSpan delay, Func<Task> action, string purpose = "")
    {
        var expected = Interlocked.Read(ref generation);
        var token = lifetime.Token;
        _ = RunScheduledAsync(delay < TimeSpan.Zero ? TimeSpan.Zero : delay, expected, token, action, purpose);
    }
    private async Task RunScheduledAsync(TimeSpan delay, long expected, CancellationToken token, Func<Task> action, string purpose)
    {
        try
        {
            // Task.Delay cannot accept a year-9999 session lifetime. Recheck in bounded chunks.
            while (delay > TimeSpan.FromDays(1))
            {
                await DelayForPurposeAsync(TimeSpan.FromDays(1), token, purpose);
                delay -= TimeSpan.FromDays(1);
            }
            await DelayForPurposeAsync(delay, token, purpose);
            await gate.WaitAsync(token);
            try
            {
                if (!disposed && expected == Interlocked.Read(ref generation)) await action();
                if (!disposed) await MaybeAbandonAfterLoginFailureAsync();
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }
            catch (Exception ex) when (firstAttempt) { await FailAsync(ex); }
            finally { Publish(); gate.Release(); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
    private Task DelayForPurposeAsync(TimeSpan delay, CancellationToken token, string purpose)
        => DelayWithPurposeAsync?.Invoke(delay, token, purpose) ?? delayAsync(delay, token);
    private void OnTunnelDown(object? sender, EventArgs e) => Schedule(TimeSpan.Zero, () =>
    {
        WriteJournal("隧道掉线"); // 回调在串行锁内执行,不写在事件线程上。
        return ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelDown)));
    });

    public async Task ChangeSessionSourceAsync(Func<ISessionSource?> change, string notice)
    {
        await gate.WaitAsync();
        try
        {
            if (protection || machine.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting)
                throw new InvalidOperationException("请先点击断开，再更换配对文件。");
            EndFirstAttempt();
            var next = change();
            lifetime.Cancel();
            Interlocked.Increment(ref generation);
            sessionSource = next;
            session = null;
            message = notice;
        }
        finally { Publish(); gate.Release(); }
    }

    private async Task FailAsync(Exception? cause = null)
    {
        WriteJournal(cause is null ? "连接失败：原因未知" : "连接失败：" + ConnectJournal.Describe(cause));
        if (firstAttempt)
        {
            // 从没连上的那次尝试失败:放弃并恢复原网络,不停在「需人工处理」。
            await AbandonAsync(cause);
            return;
        }
        lifetime.Cancel();
        message = "操作失败，请联系管理员；断网保护没有自动撤销。";
        var transition = machine.Handle(new(ConnectionEventKind.OperationFailed));
        try { await ExecuteAsync(transition); }
        catch (Exception ex) when (IsOperational(ex)) { message = "连接内核未能停止，请联系管理员；断网保护保留。"; }
        if (cause is FirewallIneffectiveException) message = cause.Message;
    }

    private enum UndoState { NotNeeded, Removed, Failed }

    private static string UndoText(UndoState state) => state switch
    {
        UndoState.Removed => "成功",
        UndoState.Failed => "失败",
        _ => "不需要"
    };

    private static string ReasonSentence(Exception? cause) => cause switch
    {
        WfpUnavailableException => "原因：系统过滤层的保护没能建立。",
        RouteGuardUnavailableException => "原因：兜底路由没能建立。",
        NicGuardException nic => $"原因：没能关闭网卡「{nic.AdapterName ?? "未知"}」的 IPv6。",
        FirewallIneffectiveException => "原因：系统防火墙没有开启，或被策略覆盖。",
        FileNotFoundException => "原因：未找到连接内核。",
        TimeoutException or OperationCanceledException => "原因：有一步操作超过时限没有完成。",
        _ => "原因已写入诊断记录，请导出诊断发给管理员。"
    };

    private static string ReasonPhrase(Exception? cause) => cause switch
    {
        WfpUnavailableException => "过滤层没建成",
        RouteGuardUnavailableException => "兜底路由没建成",
        NicGuardException => "网卡 IPv6 没关成",
        FirewallIneffectiveException => "系统防火墙没生效",
        FileNotFoundException => "未找到连接内核",
        TimeoutException or OperationCanceledException => "操作超时",
        _ => "其他"
    };

    /// <summary>放弃并恢复:停隧道、撤销已套上的断网保护、恢复网卡与环境,状态回未连接;最后发一次快照。</summary>
    private async Task AbandonAsync(Exception? cause, string? phrase = null, string? reason = null, string? fixedMessage = null)
    {
        lifetime.Cancel();
        Interlocked.Increment(ref generation);
        var stopped = true;
        try { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.AttemptAbandoned))); }
        catch (Exception ex)
        {
            WriteJournal("停止隧道没成功：" + ConnectJournal.Describe(ex));
            stopped = false;
        }
        var undo = UndoState.NotNeeded;
        string? nicWarning = null;
        var environmentRestored = false;
        if (stopped)
        {
            (undo, nicWarning) = await RemoveProtectionAsync();
            if (undo != UndoState.Failed)
            {
                try { environmentRestored = await RestoreEnvironmentAsync(); }
                catch (Exception ex)
                {
                    WriteJournal("恢复环境没成功：" + ConnectJournal.Describe(ex));
                    environmentRestored = false;
                }
                session = null;
                guardStatus = "";
            }
        }
        if (!stopped || undo == UndoState.Failed)
        {
            // 内核停不下来或保护撤不掉:停在需人工处理,不再做环境恢复,保护保持。
            try { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.OperationFailed))); }
            catch (Exception) { }
            message = !stopped
                ? "连接内核未能停止，请联系管理员；断网保护保留。"
                : AbandonNotRestored + (reason ?? ReasonSentence(cause));
            if (!stopped) undo = UndoState.NotNeeded;
        }
        else
        {
            message = (fixedMessage ?? AbandonRestored + (reason ?? ReasonSentence(cause)))
                + (nicWarning is null ? "" : " " + nicWarning)
                + (environmentRestored ? "" : " 时区或浏览器设置未能恢复，请联系管理员。");
        }
        EndFirstAttempt();
        RaiseAttemptAbandoned();
        WriteJournal("放弃并恢复：" + (phrase ?? ReasonPhrase(cause)) + "，撤销=" + UndoText(undo));
        Publish();
    }

    /// <summary>撤销本进程套上的断网保护并恢复网卡;没套过就不碰系统防火墙。</summary>
    private async Task<(UndoState State, string? Warning)> RemoveProtectionAsync()
    {
        if (!protection) return (UndoState.NotNeeded, null);
        try { await firewall.RemoveAsync(); }
        catch (Exception ex)
        {
            WriteJournal("撤销断网保护没成功：" + ConnectJournal.Describe(ex));
            return (UndoState.Failed, null);
        }
        var removeText = firewall.LastRemoveWarning;
        if (removeText is not null)
            WriteJournal("撤销断网保护：没有恢复记录，默认出站已按 Windows 默认改回允许");
        protection = false;
        protectionVerified = false;
        firewallWarning = null;
        reapWarning = null;
        // 这条路撤保护不经过状态迁移,要自己把巡检停掉。
        SyncPatrol();
        string? warning = null;
        if (nicGuard is not null)
        {
            try { warning = await nicGuard.RestoreAsync(); }
            catch (Exception ex) { WriteJournal("恢复网卡没成功：" + ConnectJournal.Describe(ex)); }
        }
        if (removeText is null) return (UndoState.Removed, warning);
        return (UndoState.Removed, warning is null ? removeText : removeText + " " + warning);
    }

    /// <summary>首次尝试期间落到需重新登录或需人工处理且已套上保护:只撤保护、恢复环境,状态与提示不动。</summary>
    private async Task MaybeAbandonAfterLoginFailureAsync()
    {
        if (!firstAttempt || !protection || machine.State is not (ConnectionState.NeedsLogin or ConnectionState.NeedsManual)) return;
        var (undo, warning) = await RemoveProtectionAsync();
        if (undo != UndoState.Failed)
        {
            message += " 已恢复原来的网络。";
            if (warning is not null) message += " " + warning;
            var environmentRestored = false;
            try { environmentRestored = await RestoreEnvironmentAsync(); }
            catch (Exception ex)
            {
                WriteJournal("恢复环境没成功：" + ConnectJournal.Describe(ex));
                environmentRestored = false;
            }
            if (!environmentRestored) message += " 时区或浏览器设置未能恢复，请联系管理员。";
        }
        EndFirstAttempt();
        RaiseAttemptAbandoned();
        WriteJournal("放弃并恢复：登录状态失效，撤销=" + UndoText(undo));
        Publish();
    }

    private void EndFirstAttempt()
    {
        firstAttempt = false;
        firstBackoffs = 0;
    }

    private void RaiseAttemptAbandoned()
    {
        try { AttemptAbandoned?.Invoke(); }
        catch (Exception) { } // 订阅者抛错不能改变已经完成的恢复结果。
    }

    private void WriteJournal(string line)
    {
        try { Journal?.Invoke(line); }
        catch (Exception) { } // 记录写不进不影响连接与恢复。
    }

    /// <summary>恢复记录的状态:读取失败只写「读不到」,不让记录读取影响连接流程。</summary>
    private string PendingRecordText()
    {
        try { return firewall.HasPendingState ? "有" : "无"; }
        catch (Exception) { return "读不到"; }
    }

    /// <summary>状态与上次写进记录的不同时,补一行「状态：旧→新」。</summary>
    private void JournalState()
    {
        var state = machine.State;
        if (state == journaledState) return;
        WriteJournal("状态：" + ConnectJournal.StateName(journaledState) + "→" + ConnectJournal.StateName(state));
        journaledState = state;
    }

    /// <summary>巡检文字只在变化时写一行;从异常回到正常单独写「巡检：恢复正常」。</summary>
    private void JournalPatrol()
    {
        if (guardStatus.Length == 0) return;
        if (guardStatus == "正常")
        {
            if (journaledPatrol.Length == 0) return;
            WriteJournal("巡检：恢复正常");
            journaledPatrol = "";
            return;
        }
        if (guardStatus.StartsWith("已为新出现的", StringComparison.Ordinal)) return;
        if (guardStatus == journaledPatrol) return;
        WriteJournal("巡检：" + ConnectJournal.Clean(guardStatus));
        journaledPatrol = guardStatus;
    }

    private static IPAddress[] NodeIps(SessionResponse value)
    {
        if (!IPAddress.TryParse(value.Node.Host, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidDataException("服务器必须下发 IPv4 节点地址。");
        return [ip];
    }
    private static bool IsOperational(Exception ex) => ex is IOException or UnauthorizedAccessException or
        System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or
        InvalidOperationException or ArgumentException or TimeoutException or System.ComponentModel.Win32Exception or OperationCanceledException;
    private static string AuthMessage(AuthResult result) => result switch
    {
        AuthResult.InviteNotFound => "邀请码不存在。", AuthResult.Expired => "账号已到期。",
        AuthResult.Disabled => "账号已停用。", AuthResult.DeviceLimit => "设备数量已达到上限。",
        AuthResult.Revoked => "本设备已被吊销。", AuthResult.RateLimited => "请求过于频繁，请稍后重试。",
        AuthResult.Network => "无法连接服务器，请检查网络。", AuthResult.InvalidParameters => "填写内容不正确。",
        AuthResult.InvalidToken => "登录凭据已失效，请重新登录。", _ => "服务器返回异常，请联系管理员。"
    };
    private void Publish() => Changed?.Invoke(Snapshot);
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        lifetime.Cancel();
        patrolLifetime.Cancel();
        Interlocked.Increment(ref generation);
        tunnel.TunnelDown -= OnTunnelDown;
        if (addressChanges is not null) addressChanges.Changed -= OnAddressChanged;
        if (addressChanges is IDisposable disposableChanges) disposableChanges.Dispose();
        tunnel.Dispose();
        if (exitProbe is IDisposable disposableProbe) disposableProbe.Dispose();
        // Closing the UI is not UserDisconnect. Leave the firewall snapshot for next-start recovery.
    }
}
