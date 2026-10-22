using System.Net;
using System.Net.Sockets;
using WinClient.Core.Auth;
using WinClient.Core.Pairing;
using WinClient.Core.Firewall;
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
    internal static readonly TimeSpan ExitCheckDelay = TimeSpan.FromSeconds(3);
    internal static readonly TimeSpan ExitCheckRetry = TimeSpan.FromSeconds(5);
    internal const int ExitCheckAttempts = 5;
    internal static readonly TimeSpan ExitRecheckInterval = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan PatrolInterval = TimeSpan.FromSeconds(60);
    // 测试可同时记录所有用途；未注入时仍使用原有 delayAsync，不改变调度行为。
    internal Func<TimeSpan, CancellationToken, string, Task>? DelayWithPurposeAsync { get; set; }
    private readonly IExitProbe? exitProbe;
    private readonly IEnvironmentEnforcer? environment;
    private readonly IEnvironmentSettingsStore? environmentSettings;
    private readonly IIpv6Probe? ipv6Probe;
    private readonly Action<EnvironmentReport>? reportSink;
    private readonly IRoutingSettingsStore? routingSettings;
    private readonly string serviceProcessPath;
    private RoutingPolicy activeRouting = RoutingPolicy.Global;
    private string selfCheckStatus = "未检测";
    private bool environmentApplied;
    private string environmentStatus = "未应用";
    private string exitStatus = "未检测";
    private string exitIp = "";
    private string guardStatus = "";
    private object? exitCycle;
    private bool patrolScheduled;
    private object? patrolCycle;
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
    private bool disposed;
    private long generation;
    private string message = "";
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
        IRoutingSettingsStore? routingSettings = null, string? serviceProcessPath = null)
        : this(auth is null ? null : new AuthServerSessionSource(auth, credentials), firewall, tunnel, program, device,
            authEndpoint: authEndpoint, exitProbe: exitProbe, environment: environment, environmentSettings: environmentSettings,
            ipv6Probe: ipv6Probe, reportSink: reportSink, routingSettings: routingSettings, serviceProcessPath: serviceProcessPath) { }

    public ClientController(ISessionSource? sessionSource, IKillSwitch firewall,
        ITunnelTransport tunnel, string program, DeviceInfo device, Func<TimeSpan, CancellationToken, Task>? delayAsync = null,
        AuthEndpoint? authEndpoint = null, IExitProbe? exitProbe = null,
        IEnvironmentEnforcer? environment = null, IEnvironmentSettingsStore? environmentSettings = null,
        IIpv6Probe? ipv6Probe = null, Action<EnvironmentReport>? reportSink = null,
        IRoutingSettingsStore? routingSettings = null, string? serviceProcessPath = null)
    {
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
        this.reportSink = reportSink;
        this.routingSettings = routingSettings;
        this.serviceProcessPath = serviceProcessPath ?? Environment.ProcessPath ?? "WinClient.App.exe";
        tunnel.TunnelDown += OnTunnelDown;
    }

    public async Task InitializeAsync(bool autoConnect = true, bool keepProtection = false)
    {
        const string protectionNotice = "后台服务已重新启动，断网保护保持，正在恢复连接。";
        var keptProtection = false;
        string? warning = null;
        await gate.WaitAsync();
        try
        {
            if (keepProtection && firewall.HasPendingState &&
                (sessionSource is PairingSessionSource or AuthServerSessionSource { HasCredentials: true }))
            {
                protection = true;
                protectionVerified = true;
                message = protectionNotice;
                keptProtection = true;
                environmentApplied = environment?.HasPendingState ?? false;
            }
            else
            {
                warning = await firewall.RecoverAsync();
                if (warning is not null) message = warning + (sessionSource is null ? " 未配置服务器。" : "");
                else if (sessionSource is null) message = "未配置服务器";
                if (!await RestoreEnvironmentAsync())
                {
                    const string environmentWarning = "启动时未能恢复上次的时区或浏览器设置,请联系管理员。";
                    warning = warning is null ? environmentWarning : warning + " " + environmentWarning;
                    message += " " + environmentWarning;
                }
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
            await ConnectAsync();
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
            try { if (sessionSource is PairingSessionSource || sessionSource is AuthServerSessionSource { HasCredentials: true }) await ConnectAsync(); }
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

    public async Task ConnectAsync()
    {
        await gate.WaitAsync();
        try
        {
            if (sessionSource is null) { message = "未配置服务器"; return; }
            if (machine.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting) return;
            activeRouting = routingSettings?.Read() ?? RoutingPolicy.Global;
            if (activeRouting.Mode == RoutingMode.Apps && activeRouting.Apps.Count == 0)
            { message = "仅指定程序模式至少要选一个程序,请先添加程序或切回全部流量。"; return; }
            if (firewall.HasPendingState && (firewall.PendingMode ?? "global") != ModeName(activeRouting))
            { message = "上次的断网保护记录与当前代理范围不一致,请先用原来的代理范围连接并正常断开,或重启后台服务后再试。"; return; }
            lifetime.Cancel();
            lifetime.Dispose();
            lifetime = new();
            Interlocked.Increment(ref generation);
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.UserConnect)));
            await FetchSessionAsync();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }
        finally { Publish(); gate.Release(); }
    }

    public async Task DisconnectAsync()
    {
        lifetime.Cancel();
        Interlocked.Increment(ref generation);
        await gate.WaitAsync();
        try
        {
            guardStatus = "";
            // Execution is ordered: a failure to stop the tunnel must not proceed to Remove.
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.UserDisconnect)));
            session = null;
            var environmentRestored = await RestoreEnvironmentAsync();
            message = environmentRestored ? "已断开，原网络设置已恢复。"
                : "已断开,原网络设置已恢复;但时区或浏览器设置未能恢复,请联系管理员。";
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
        if (response.Result != AuthResult.Ok || response.Value is null)
        { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.AuthRejected, response.Result))); return; }
        var next = response.Value;
        if (next.SessionExpiresAt <= DateTimeOffset.UtcNow || next.AccountExpiresAt <= DateTimeOffset.UtcNow)
        { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired))); return; }
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
            sessionSource is AuthServerSessionSource ? authEndpoint : null);

    private static DateTimeOffset Expiry(SessionResponse value) =>
        value.SessionExpiresAt < value.AccountExpiresAt ? value.SessionExpiresAt : value.AccountExpiresAt;

    private async Task ExecuteAsync(Transition transition)
    {
        try { await ExecuteEffectsAsync(transition); }
        finally { UpdateMonitoring(); }
    }

    private async Task ExecuteEffectsAsync(Transition transition)
    {
        Publish();
        foreach (var effect in transition.Effects)
        {
            switch (effect.Kind)
            {
                case EffectKind.ShowMessage:
                    message = sessionSource is PairingSessionSource && transition.State == ConnectionState.NeedsManual && machine.HasSession
                        ? "连不上澳洲出口，出口地址可能已变，请在小主机上重新导出配对文件再导入。断网保护仍保持。"
                        : effect.Message ?? "";
                    break;
                case EffectKind.ApplyKillSwitch:
                    var held = protectionVerified;
                    protection = true; // Even partial Apply must be treated as requiring explicit recovery.
                    try
                    {
                        if (activeRouting.Mode == RoutingMode.Apps) await firewall.ApplyAppsAsync(activeRouting.Apps);
                        else await firewall.ApplyAsync(NodeIps(session!), program, session!.Node.Hy2Port, session.Node.RealityPort,
                                sessionSource is AuthServerSessionSource ? authEndpoint : null);
                        protectionVerified = true;
                        firewallWarning = null;
                    }
                    catch (FirewallIneffectiveException) when (held)
                    {
                        firewallWarning = KeepTunnelWarning;
                        guardStatus = KeepTunnelWarning;
                        message = KeepTunnelWarning;
                    }
                    break;
                case EffectKind.UpdateKillSwitchNode:
                    if (activeRouting.Mode != RoutingMode.Apps)
                        await firewall.UpdateNodeAsync(effect.NewIps!, program, session!.Node.Hy2Port, session.Node.RealityPort);
                    break;
                case EffectKind.RemoveKillSwitch:
                    await firewall.RemoveAsync(); protection = false; protectionVerified = false; firewallWarning = null; break;
                case EffectKind.StopTunnel: tunnel.Stop(); break;
                case EffectKind.StartTunnel:
                    if (session is null || session.SessionExpiresAt <= DateTimeOffset.UtcNow || session.AccountExpiresAt <= DateTimeOffset.UtcNow)
                    { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired))); break; }
                    try
                    {
                        await tunnel.StartAsync(RenderedConfiguration(session), lifetime.Token);
                        lifetime.Token.ThrowIfCancellationRequested();
                        await ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelUp)));
                        message = firewallWarning ?? "虚拟网卡已就绪。";
                        await ApplyEnvironmentAsync();
                    }
                    catch (FileNotFoundException ex)
                    {
                        await FailAsync(ex);
                        message = "未找到连接内核，请联系管理员配置 sing-box.exe 路径。";
                    }
                    catch (InvalidDataException) { throw; }
                    catch (Exception ex) when (ex is IOException or TimeoutException)
                    { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelDown))); }
                    break;
                case EffectKind.ScheduleBackoff:
                    Schedule(effect.Delay!.Value, async () =>
                    {
                        var next = machine.Handle(new(ConnectionEventKind.BackoffElapsed));
                        await ExecuteAsync(next);
                        if (machine.State == ConnectionState.Reconnecting && !next.Effects.Any(e => e.Kind == EffectKind.StartTunnel))
                            await FetchSessionAsync();
                    }, "退避");
                    break;
            }
        }
    }

    /// <summary>在迁移处理完成后统一更新监测；所有回调沿用串行锁、代数与生命周期。</summary>
    private void UpdateMonitoring()
    {
        if (machine.State != ConnectionState.Connected)
        {
            selfCheckStatus = "未检测";
            exitStatus = "未检测";
            exitIp = "";
            if (activeRouting.Mode != RoutingMode.Apps || machine.State != ConnectionState.Reconnecting) exitCycle = null;
        }
        else if (session is not null && exitProbe is not null && exitCycle is null)
        {
            exitCycle = new object();
            exitStatus = "核验中";
            ScheduleExitCheck(ExitCheckDelay, exitCycle, 1);
        }
        if (!ShouldPatrol)
        {
            patrolScheduled = false;
            patrolCycle = null;
        }
        else if (!patrolScheduled)
        {
            patrolCycle = new object();
            SchedulePatrol(patrolCycle);
        }
    }

    private bool ShouldPatrol => protection && machine.State is ConnectionState.Connected or ConnectionState.Reconnecting;

    private void ScheduleExitCheck(TimeSpan wait, object cycle, int attempt)
        => Schedule(wait, () => CheckExitAsync(cycle, attempt), "出口核验");

    private async Task CheckExitAsync(object cycle, int attempt)
    {
        // 同一生命周期内也可能先断线后重连；连接轮次防止旧探测重复续排。
        if (!ReferenceEquals(cycle, exitCycle) || session is null) return;
        if (machine.State != ConnectionState.Connected)
        {
            if (activeRouting.Mode == RoutingMode.Apps) ScheduleExitCheck(ExitRecheckInterval, cycle, 1);
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
            exitIp = address.ToString();
            var matches = IPAddress.TryParse(session.Node.Host, out var expected) && address.Equals(expected);
            exitStatus = matches ? "已核验" : "不一致";
            if (activeRouting.Mode == RoutingMode.Apps) exitStatus += "(后台服务出口)";
            if (!matches) message = "出口地址与澳洲节点不一致,请联系管理员;断网保护保持,未自动断开。";
        }
        else if (attempt < ExitCheckAttempts)
        {
            ScheduleExitCheck(ExitCheckRetry, cycle, attempt + 1);
            return;
        }
        else
        {
            exitStatus = "无法核验";
            exitIp = "";
        }
        await CheckEnvironmentAsync(exit);
        if (!lifetime.IsCancellationRequested && !disposed) ScheduleExitCheck(ExitRecheckInterval, cycle, 1);
    }

    private async Task CheckEnvironmentAsync(ExitProbeResult? exit)
    {
        selfCheckStatus = "检测中";
        Publish();
        var policy = (environmentSettings?.Read() ?? EnvironmentSettingsStore.Default).ForNode(session?.Node);
        EnvironmentInspection? inspection = null;
        if (policy.Enabled && environment is not null)
        {
            try { inspection = await environment.InspectAsync(); }
            catch (Exception ex) when (IsOperational(ex)) { }
        }
        if (lifetime.IsCancellationRequested || disposed) return;
        bool? ipv6 = null;
        try { if (activeRouting.Mode != RoutingMode.Apps && ipv6Probe is not null) ipv6 = await ipv6Probe.CanReachAsync(lifetime.Token); }
        catch (Exception) { } // 探测异常仅代表本项无法核验，不进入连接失败路径。
        if (lifetime.IsCancellationRequested || disposed) return;
        var report = EnvironmentSelfCheck.Evaluate(new(exit, session!.Node.Host, policy.ExpectedCountry,
            policy.Enabled, environmentApplied, policy.Target, inspection, ipv6,
            RenderedConfiguration(session),
            DateTimeOffset.UtcNow) { Routing = activeRouting });
        selfCheckStatus = report.Summary;
        try { reportSink?.Invoke(report); }
        catch (Exception ex) when (IsOperational(ex)) { } // 写报告失败不影响已完成的检查与连接。
    }

    private void SchedulePatrol(object cycle)
    {
        patrolScheduled = true;
        Schedule(PatrolInterval, () => PatrolAsync(cycle), "巡检");
    }

    private async Task PatrolAsync(object cycle)
    {
        if (!ReferenceEquals(cycle, patrolCycle) || !ShouldPatrol) return;
        try
        {
            var report = activeRouting.Mode == RoutingMode.Apps
                ? await firewall.PatrolAsync(KillSwitchPlanner.AppRuleNames(activeRouting.Apps.Count), enforceDefaultBlock: false)
                : await firewall.PatrolAsync(KillSwitchPlanner.ExpectedRuleNames(sessionSource is AuthServerSessionSource));
            if (lifetime.IsCancellationRequested || disposed) return;
            if (report.MissingRules.Count > 0)
            {
                if (session is not null)
                {
                    if (activeRouting.Mode == RoutingMode.Apps) await firewall.ApplyAppsAsync(activeRouting.Apps);
                    else await firewall.ApplyAsync(NodeIps(session), program, session.Node.Hy2Port, session.Node.RealityPort,
                            sessionSource is AuthServerSessionSource ? authEndpoint : null);
                    guardStatus = $"已重建 {report.MissingRules.Count} 条本项目规则";
                }
                else guardStatus = "巡检失败,下一轮重试";
            }
            else if (!report.Clean) guardStatus = $"已重新收紧 {report.Reenforced.Count + report.NewlyDisabled.Count} 条规则";
            else guardStatus = "正常";
            if (firewallWarning is not null)
            {
                firewallWarning = null;
                protectionVerified = true;
                message = "断网保护已重新生效。";
            }
        }
        catch (FirewallIneffectiveException)
        {
            guardStatus = "系统防火墙已被关闭或被策略覆盖,断网保护可能失效,请立即在 Windows 安全中心开启防火墙或联系管理员";
            message = guardStatus;
        }
        catch (Exception ex) when (IsOperational(ex)) { guardStatus = "巡检失败,下一轮重试"; }
        finally
        {
            Publish();
            if (!disposed && !lifetime.IsCancellationRequested && ShouldPatrol && ReferenceEquals(cycle, patrolCycle)) SchedulePatrol(cycle);
        }
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
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex) when (IsOperational(ex)) { await FailAsync(ex); }
            finally { Publish(); gate.Release(); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
    private Task DelayForPurposeAsync(TimeSpan delay, CancellationToken token, string purpose)
        => DelayWithPurposeAsync?.Invoke(delay, token, purpose) ?? delayAsync(delay, token);
    private void OnTunnelDown(object? sender, EventArgs e) => Schedule(TimeSpan.Zero,
        () => ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelDown))));

    public async Task ChangeSessionSourceAsync(Func<ISessionSource?> change, string notice)
    {
        await gate.WaitAsync();
        try
        {
            if (protection || machine.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting)
                throw new InvalidOperationException("请先点击断开，再更换配对文件。");
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
        lifetime.Cancel();
        message = "操作失败，请联系管理员；断网保护没有自动撤销。";
        var transition = machine.Handle(new(ConnectionEventKind.OperationFailed));
        try { await ExecuteAsync(transition); }
        catch (Exception ex) when (IsOperational(ex)) { message = "连接内核未能停止，请联系管理员；断网保护保留。"; }
        if (cause is FirewallIneffectiveException) message = cause.Message;
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
        Interlocked.Increment(ref generation);
        tunnel.TunnelDown -= OnTunnelDown;
        tunnel.Dispose();
        if (exitProbe is IDisposable disposableProbe) disposableProbe.Dispose();
        // Closing the UI is not UserDisconnect. Leave the firewall snapshot for next-start recovery.
    }
}
