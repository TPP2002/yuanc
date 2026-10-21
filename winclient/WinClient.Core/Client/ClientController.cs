using System.Net;
using System.Net.Sockets;
using WinClient.Core.Auth;
using WinClient.Core.Firewall;
using WinClient.Core.State;
using WinClient.Core.Storage;

namespace WinClient.Core.Client;

public sealed record ClientSnapshot(ConnectionState State, string Status, string Message, bool ProtectionActive)
{
    public string Mode { get; init; } = "未配置";
}

/// <summary>Owns the serialized user flow, effects and session lifetime; no UI dependencies.</summary>
public sealed class ClientController : IDisposable
{
    private ISessionSource? sessionSource;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
    private readonly IKillSwitch firewall;
    private readonly ITunnelTransport tunnel;
    private readonly string program;
    private readonly DeviceInfo device;
    private readonly ConnectionStateMachine machine = new();
    private readonly SemaphoreSlim gate = new(1, 1);
    private CancellationTokenSource lifetime = new();
    private SessionResponse? session;
    private bool protection;
    private bool disposed;
    private long generation;
    private string message = "";
    public ClientSnapshot Snapshot => new(machine.State, machine.StatusText, message, protection) { Mode = sessionSource?.Mode ?? "未配置" };
    public event Action<ClientSnapshot>? Changed;

    public ClientController(AuthApiClient? auth, ICredentialStore credentials, IKillSwitch firewall,
        ITunnelTransport tunnel, string program, DeviceInfo device)
        : this(auth is null ? null : new AuthServerSessionSource(auth, credentials), firewall, tunnel, program, device) { }

    public ClientController(ISessionSource? sessionSource, IKillSwitch firewall,
        ITunnelTransport tunnel, string program, DeviceInfo device, Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        this.sessionSource = sessionSource;
        this.delayAsync = delayAsync ?? ((delay, token) => Task.Delay(delay, token));
        this.firewall = firewall;
        this.tunnel = tunnel;
        this.program = program;
        this.device = device;
        tunnel.TunnelDown += OnTunnelDown;
    }

    public async Task InitializeAsync(bool autoConnect = true)
    {
        string? warning = null;
        await gate.WaitAsync();
        try
        {
            warning = await firewall.RecoverAsync();
            if (warning is not null) message = warning + (sessionSource is null ? " 未配置服务器。" : "");
            else if (sessionSource is null) message = "未配置服务器";
        }
        catch (Exception ex) when (IsOperational(ex))
        {
            await FailAsync();
            message = "启动时未能恢复上次的断网保护设置，恢复记录已保留；请联系管理员处理后重新启动后台服务。";
        }
        finally { Publish(); gate.Release(); }
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
            lifetime.Cancel();
            lifetime.Dispose();
            lifetime = new();
            Interlocked.Increment(ref generation);
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.UserConnect)));
            await FetchSessionAsync();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(); }
        finally { Publish(); gate.Release(); }
    }

    public async Task DisconnectAsync()
    {
        lifetime.Cancel();
        Interlocked.Increment(ref generation);
        await gate.WaitAsync();
        try
        {
            // Execution is ordered: a failure to stop the tunnel must not proceed to Remove.
            await ExecuteAsync(machine.Handle(new(ConnectionEventKind.UserDisconnect)));
            session = null;
            message = "已断开，原网络设置已恢复。";
        }
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(); }
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
        catch (Exception ex) when (IsOperational(ex)) { await FailAsync(); }
        finally { Publish(); gate.Release(); }
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
        var nextIps = NodeIps(next);
        _ = TunnelTransport.RenderConfiguration(next.SingboxConfig); // Validate before installing rules.
        var previous = session;
        session = next;
        if (protection && previous is not null)
        {
            if (!NodeIps(previous).SequenceEqual(nextIps) || previous.Node.Hy2Port != next.Node.Hy2Port || previous.Node.RealityPort != next.Node.RealityPort)
                await ExecuteAsync(machine.Handle(new(ConnectionEventKind.NodeChanged, OldIps: NodeIps(previous), NewIps: nextIps)));
            // Refresh can change credentials as well as addresses: restart under the existing protection.
            await ExecuteAsync(machine.Handle(new(machine.HasSession ? ConnectionEventKind.TunnelDown : ConnectionEventKind.SessionOk)));
        }
        else await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionOk)));
        ScheduleExpiry(next);
    }

    private async Task ExecuteAsync(Transition transition)
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
                    protection = true; // Even partial Apply must be treated as requiring explicit recovery.
                    await firewall.ApplyAsync(NodeIps(session!), program, session!.Node.Hy2Port, session.Node.RealityPort);
                    break;
                case EffectKind.UpdateKillSwitchNode:
                    await firewall.UpdateNodeAsync(effect.NewIps!, program, session!.Node.Hy2Port, session.Node.RealityPort);
                    break;
                case EffectKind.RemoveKillSwitch:
                    await firewall.RemoveAsync(); protection = false; break;
                case EffectKind.StopTunnel: tunnel.Stop(); break;
                case EffectKind.StartTunnel:
                    if (session is null || session.SessionExpiresAt <= DateTimeOffset.UtcNow || session.AccountExpiresAt <= DateTimeOffset.UtcNow)
                    { await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired))); break; }
                    try
                    {
                        await tunnel.StartAsync(session.SingboxConfig, lifetime.Token);
                        lifetime.Token.ThrowIfCancellationRequested();
                        await ExecuteAsync(machine.Handle(new(ConnectionEventKind.TunnelUp)));
                        message = "虚拟网卡已就绪。";
                    }
                    catch (FileNotFoundException)
                    {
                        await FailAsync();
                        message = "未找到连接内核，请联系管理员配置 sing-box.exe 路径。";
                    }
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
                    });
                    break;
            }
        }
    }

    private void ScheduleExpiry(SessionResponse value)
    {
        var expiry = value.SessionExpiresAt < value.AccountExpiresAt ? value.SessionExpiresAt : value.AccountExpiresAt;
        Schedule(expiry - DateTimeOffset.UtcNow, async () =>
        {
            if (ReferenceEquals(value, session)) await ExecuteAsync(machine.Handle(new(ConnectionEventKind.SessionExpired)));
        });
    }
    private void Schedule(TimeSpan delay, Func<Task> action)
    {
        var expected = Interlocked.Read(ref generation);
        var token = lifetime.Token;
        _ = RunScheduledAsync(delay < TimeSpan.Zero ? TimeSpan.Zero : delay, expected, token, action);
    }
    private async Task RunScheduledAsync(TimeSpan delay, long expected, CancellationToken token, Func<Task> action)
    {
        try
        {
            // Task.Delay cannot accept a year-9999 session lifetime. Recheck in bounded chunks.
            while (delay > TimeSpan.FromDays(1))
            {
                await delayAsync(TimeSpan.FromDays(1), token);
                delay -= TimeSpan.FromDays(1);
            }
            await delayAsync(delay, token);
            await gate.WaitAsync(token);
            try
            {
                if (!disposed && expected == Interlocked.Read(ref generation)) await action();
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex) when (IsOperational(ex)) { await FailAsync(); }
            finally { Publish(); gate.Release(); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
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

    private async Task FailAsync()
    {
        lifetime.Cancel();
        message = "操作失败，请联系管理员；断网保护没有自动撤销。";
        var transition = machine.Handle(new(ConnectionEventKind.OperationFailed));
        try { await ExecuteAsync(transition); }
        catch (Exception ex) when (IsOperational(ex)) { message = "连接内核未能停止，请联系管理员；断网保护保留。"; }
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
        // Closing the UI is not UserDisconnect. Leave the firewall snapshot for next-start recovery.
    }
}
