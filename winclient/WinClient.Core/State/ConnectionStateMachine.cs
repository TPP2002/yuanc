using WinClient.Core.Auth;

namespace WinClient.Core.State;

public enum ConnectionState { Disconnected, Connecting, Connected, Reconnecting, NeedsLogin, NeedsManual }
public enum ConnectionEventKind
{
    UserConnect, UserDisconnect, SessionOk, SessionExpired, AuthRejected,
    TunnelUp, TunnelDown, BackoffElapsed, NodeChanged, OperationFailed
}
public enum EffectKind { StartTunnel, StopTunnel, ApplyKillSwitch, RemoveKillSwitch, ScheduleBackoff, ShowMessage, UpdateKillSwitchNode }
public sealed record ConnectionEvent(ConnectionEventKind Kind, AuthResult? AuthResult = null,
    IReadOnlyList<System.Net.IPAddress>? OldIps = null, IReadOnlyList<System.Net.IPAddress>? NewIps = null);
public sealed record ConnectionEffect(EffectKind Kind, TimeSpan? Delay = null, string? Message = null,
    IReadOnlyList<System.Net.IPAddress>? OldIps = null, IReadOnlyList<System.Net.IPAddress>? NewIps = null);
public sealed record Transition(ConnectionState State, IReadOnlyList<ConnectionEffect> Effects);

/// <summary>
/// Pure event-driven policy. The controller serializes events and cancels stale timers/operations.
/// A session must be accepted before a tunnel can start. Time and processes are external effects.
/// </summary>
public sealed class ConnectionStateMachine
{
    private static readonly int[] BackoffSeconds = [2, 4, 8, 16, 32, 60];
    private int retriesScheduled;
    private int capRetriesScheduled;
    private bool sessionAccepted;
    private bool awaitingBackoff;

    public ConnectionState State { get; private set; } = ConnectionState.Disconnected;
    public bool KillSwitchRequired { get; private set; }
    public bool HasSession => sessionAccepted;

    public string StatusText => State switch
    {
        ConnectionState.Connected => "已连接",
        ConnectionState.Connecting => "重连中",
        ConnectionState.Reconnecting => "重连中",
        ConnectionState.NeedsLogin => "需重新登录",
        ConnectionState.NeedsManual => "需人工处理",
        _ => "未连接"
    };

    public Transition Handle(ConnectionEvent input)
    {
        var effects = new List<ConnectionEffect>();
        if (input.Kind == ConnectionEventKind.UserDisconnect)
        {
            State = ConnectionState.Disconnected;
            sessionAccepted = false;
            KillSwitchRequired = false;
            ResetBackoff();
            effects.Add(new(EffectKind.StopTunnel));
            effects.Add(new(EffectKind.RemoveKillSwitch));
            return Finish(effects);
        }

        if (input.Kind == ConnectionEventKind.UserConnect)
        {
            if (State is ConnectionState.Disconnected or ConnectionState.NeedsLogin or ConnectionState.NeedsManual)
            {
                State = ConnectionState.Connecting;
                sessionAccepted = false;
                ResetBackoff();
                effects.Add(new(EffectKind.ShowMessage, Message: "正在验证登录状态。"));
            }
            return Finish(effects);
        }

        // Ignore completions from a cancelled/disconnected connection attempt.
        if (State == ConnectionState.Disconnected && input.Kind != ConnectionEventKind.OperationFailed) return Finish(effects);

        switch (input.Kind)
        {
            case ConnectionEventKind.OperationFailed:
                State = ConnectionState.NeedsManual;
                awaitingBackoff = false;
                sessionAccepted = false;
                effects.Add(new(EffectKind.StopTunnel));
                effects.Add(new(EffectKind.ShowMessage, Message: "连接操作失败，断网保护未主动撤销，请联系管理员。"));
                break;
            case ConnectionEventKind.NodeChanged when KillSwitchRequired:
                if (input.OldIps is null || input.NewIps is null || input.NewIps.Count == 0)
                    throw new ArgumentException("节点变化必须提供原地址和新地址。", nameof(input));
                effects.Add(new(EffectKind.UpdateKillSwitchNode, OldIps: input.OldIps, NewIps: input.NewIps));
                break;
            case ConnectionEventKind.SessionExpired:
                RequireLogin(effects, "登录已到期，请重新登录。");
                break;
            case ConnectionEventKind.AuthRejected:
                if (input.AuthResult is null or AuthResult.Ok)
                    throw new ArgumentException("鉴权拒绝事件必须携带失败结果。", nameof(input));
                sessionAccepted = false;
                effects.Add(new(EffectKind.StopTunnel));
                if (input.AuthResult is AuthResult.Network or AuthResult.RateLimited)
                {
                    if (State is ConnectionState.Connecting or ConnectionState.Reconnecting or ConnectionState.Connected)
                        ScheduleRetry(effects);
                }
                else if (input.AuthResult is AuthResult.InvalidToken or AuthResult.Expired or AuthResult.InviteNotFound)
                {
                    RequireLogin(effects, "登录凭据不可用，请重新登录。", stopTunnel: false);
                }
                else
                {
                    State = ConnectionState.NeedsManual;
                    awaitingBackoff = false;
                    effects.Add(new(EffectKind.ShowMessage, Message: RejectionMessage(input.AuthResult.Value)));
                }
                break;
            case ConnectionEventKind.SessionOk when State is ConnectionState.Connecting or ConnectionState.Reconnecting:
                if (sessionAccepted) break;
                sessionAccepted = true;
                awaitingBackoff = false;
                KillSwitchRequired = true;
                effects.Add(new(EffectKind.ApplyKillSwitch));
                effects.Add(new(EffectKind.StartTunnel));
                break;
            case ConnectionEventKind.TunnelUp when sessionAccepted && !awaitingBackoff &&
                    State is ConnectionState.Connecting or ConnectionState.Reconnecting:
                State = ConnectionState.Connected;
                ResetBackoff();
                break;
            case ConnectionEventKind.TunnelDown when State is ConnectionState.Connecting or ConnectionState.Connected or ConnectionState.Reconnecting:
                if (awaitingBackoff) break;
                effects.Add(new(EffectKind.StopTunnel));
                ScheduleRetry(effects);
                break;
            case ConnectionEventKind.BackoffElapsed when State == ConnectionState.Reconnecting && awaitingBackoff:
                awaitingBackoff = false;
                if (sessionAccepted)
                    effects.Add(new(EffectKind.StartTunnel));
                else
                    effects.Add(new(EffectKind.ShowMessage, Message: "正在重新验证登录状态。"));
                // When no session exists, the controller reissues /client/session, not a tunnel start.
                break;
        }
        return Finish(effects);
    }

    private void ScheduleRetry(List<ConnectionEffect> effects)
    {
        if (awaitingBackoff) return;
        if (capRetriesScheduled >= 6)
        {
            State = ConnectionState.NeedsManual;
            effects.Add(new(EffectKind.ShowMessage, Message: "多次重连仍未成功，请联系管理员。断网保护仍保持。"));
            return;
        }
        State = ConnectionState.Reconnecting;
        var seconds = BackoffSeconds[Math.Min(retriesScheduled, BackoffSeconds.Length - 1)];
        retriesScheduled++;
        if (seconds == 60) capRetriesScheduled++;
        awaitingBackoff = true;
        effects.Add(new(EffectKind.ScheduleBackoff, TimeSpan.FromSeconds(seconds)));
    }

    private void RequireLogin(List<ConnectionEffect> effects, string message, bool stopTunnel = true)
    {
        sessionAccepted = false;
        awaitingBackoff = false;
        State = ConnectionState.NeedsLogin;
        if (stopTunnel) effects.Add(new(EffectKind.StopTunnel));
        effects.Add(new(EffectKind.ShowMessage, Message: message));
    }

    private void ResetBackoff()
    {
        retriesScheduled = 0;
        capRetriesScheduled = 0;
        awaitingBackoff = false;
    }

    private static string RejectionMessage(AuthResult result) => result switch
    {
        AuthResult.Disabled => "账号已停用，请联系管理员。",
        AuthResult.DeviceLimit => "设备数量已达到上限，请联系管理员。",
        AuthResult.Revoked => "本设备已被吊销，请联系管理员。",
        AuthResult.InvalidParameters => "请求参数不正确，请联系管理员。",
        _ => "服务器返回异常，请联系管理员。"
    };

    private Transition Finish(List<ConnectionEffect> effects) => new(State, effects.AsReadOnly());
}
