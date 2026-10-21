using System.Net;
using WinClient.Core.Auth;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

public sealed class StateTests
{
    internal static ConnectionStateMachine Connected()
    {
        var machine = new ConnectionStateMachine();
        machine.Handle(new(ConnectionEventKind.UserConnect));
        var accepted = machine.Handle(new(ConnectionEventKind.SessionOk));
        Assert.Equal(new[] { EffectKind.ApplyKillSwitch, EffectKind.StartTunnel }, accepted.Effects.Select(e => e.Kind));
        machine.Handle(new(ConnectionEventKind.TunnelUp));
        return machine;
    }
    [Fact]
    public void ConnectionRequiresSessionAndOnlyUserDisconnectRemovesProtection()
    {
        var machine = new ConnectionStateMachine();
        Assert.Empty(machine.Handle(new(ConnectionEventKind.SessionOk)).Effects);
        Assert.Equal(ConnectionState.Connecting, machine.Handle(new(ConnectionEventKind.UserConnect)).State);
        Assert.Empty(machine.Handle(new(ConnectionEventKind.TunnelUp)).Effects);
        machine.Handle(new(ConnectionEventKind.SessionOk));
        Assert.Equal(ConnectionState.Connected, machine.Handle(new(ConnectionEventKind.TunnelUp)).State);
        Assert.True(machine.KillSwitchRequired);
        var disconnected = machine.Handle(new(ConnectionEventKind.UserDisconnect));
        Assert.Equal(ConnectionState.Disconnected, disconnected.State);
        Assert.Contains(disconnected.Effects, e => e.Kind == EffectKind.RemoveKillSwitch);
        Assert.False(machine.KillSwitchRequired);
    }
    [Fact]
    public void RetrySequenceHasSixAttemptsAtCapThenStops()
    {
        var machine = Connected();
        foreach (var seconds in new[] { 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60 })
        {
            var failed = machine.Handle(new(ConnectionEventKind.TunnelDown));
            Assert.Equal(ConnectionState.Reconnecting, failed.State);
            Assert.Equal(TimeSpan.FromSeconds(seconds), Assert.Single(failed.Effects.Where(e => e.Kind == EffectKind.ScheduleBackoff)).Delay);
            Assert.DoesNotContain(failed.Effects, e => e.Kind == EffectKind.RemoveKillSwitch);
            Assert.Empty(machine.Handle(new(ConnectionEventKind.TunnelDown)).Effects); // Duplicate notification.
            Assert.Contains(machine.Handle(new(ConnectionEventKind.BackoffElapsed)).Effects, e => e.Kind == EffectKind.StartTunnel);
        }
        Assert.Equal(ConnectionState.NeedsManual, machine.Handle(new(ConnectionEventKind.TunnelDown)).State);
        Assert.True(machine.KillSwitchRequired);
        Assert.Empty(machine.Handle(new(ConnectionEventKind.BackoffElapsed)).Effects);
        Assert.Equal(ConnectionState.Connecting, machine.Handle(new(ConnectionEventKind.UserConnect)).State);
    }
    [Fact]
    public void SuccessfulReconnectResetsBackoffAndExpiryKeepsProtection()
    {
        var machine = Connected();
        machine.Handle(new(ConnectionEventKind.TunnelDown));
        machine.Handle(new(ConnectionEventKind.BackoffElapsed));
        Assert.Equal(ConnectionState.Connected, machine.Handle(new(ConnectionEventKind.TunnelUp)).State);
        Assert.Equal(TimeSpan.FromSeconds(2), machine.Handle(new(ConnectionEventKind.TunnelDown)).Effects.Single(e => e.Kind == EffectKind.ScheduleBackoff).Delay);
        var expired = machine.Handle(new(ConnectionEventKind.SessionExpired));
        Assert.Equal(ConnectionState.NeedsLogin, expired.State);
        Assert.Contains(expired.Effects, e => e.Kind == EffectKind.StopTunnel);
        Assert.DoesNotContain(expired.Effects, e => e.Kind == EffectKind.RemoveKillSwitch);
        Assert.Empty(machine.Handle(new(ConnectionEventKind.TunnelUp)).Effects);
        Assert.True(machine.KillSwitchRequired);
    }
    [Theory]
    [InlineData(AuthResult.InvalidToken, ConnectionState.NeedsLogin)]
    [InlineData(AuthResult.Expired, ConnectionState.NeedsLogin)]
    [InlineData(AuthResult.InviteNotFound, ConnectionState.NeedsLogin)]
    [InlineData(AuthResult.Disabled, ConnectionState.NeedsManual)]
    [InlineData(AuthResult.DeviceLimit, ConnectionState.NeedsManual)]
    [InlineData(AuthResult.Revoked, ConnectionState.NeedsManual)]
    [InlineData(AuthResult.InvalidParameters, ConnectionState.NeedsManual)]
    [InlineData(AuthResult.UnexpectedResponse, ConnectionState.NeedsManual)]
    [InlineData(AuthResult.Network, ConnectionState.Reconnecting)]
    [InlineData(AuthResult.RateLimited, ConnectionState.Reconnecting)]
    public void AuthenticationFailuresNeverRemoveRules(AuthResult reason, ConnectionState expected)
    {
        var machine = Connected();
        var result = machine.Handle(new(ConnectionEventKind.AuthRejected, reason));
        Assert.Equal(expected, result.State);
        Assert.DoesNotContain(result.Effects, e => e.Kind == EffectKind.RemoveKillSwitch);
        if (expected == ConnectionState.Reconnecting)
            Assert.DoesNotContain(machine.Handle(new(ConnectionEventKind.BackoffElapsed)).Effects, e => e.Kind == EffectKind.StartTunnel);
    }
    [Theory]
    [InlineData(ConnectionEventKind.TunnelDown)] [InlineData(ConnectionEventKind.SessionExpired)]
    [InlineData(ConnectionEventKind.OperationFailed)] [InlineData(ConnectionEventKind.BackoffElapsed)]
    [InlineData(ConnectionEventKind.SessionOk)] [InlineData(ConnectionEventKind.UserConnect)]
    [InlineData(ConnectionEventKind.TunnelUp)]
    public void NonDisconnectEventsNeverRemove(ConnectionEventKind kind)
        => Assert.DoesNotContain(Connected().Handle(new(kind)).Effects, e => e.Kind == EffectKind.RemoveKillSwitch);
    [Fact]
    public void AddressChangeHasDedicatedEffect()
    {
        var machine = Connected();
        IPAddress[] oldIps = [IPAddress.Parse("192.0.2.5")], newIps = [IPAddress.Parse("192.0.2.6")];
        var effect = Assert.Single(machine.Handle(new(ConnectionEventKind.NodeChanged, OldIps: oldIps, NewIps: newIps)).Effects);
        Assert.Equal(EffectKind.UpdateKillSwitchNode, effect.Kind);
        Assert.Equal(oldIps, effect.OldIps); Assert.Equal(newIps, effect.NewIps);
        Assert.True(machine.KillSwitchRequired);
    }
}
