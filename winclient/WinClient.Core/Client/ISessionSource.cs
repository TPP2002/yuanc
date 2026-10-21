using WinClient.Core.Auth;
using WinClient.Core.Logging;
using WinClient.Core.Pairing;
using WinClient.Core.Storage;

namespace WinClient.Core.Client;

public interface ISessionSource
{
    string Mode { get; }
    Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken cancellationToken = default);
}

public sealed class AuthServerSessionSource(AuthApiClient auth, ICredentialStore credentials) : ISessionSource
{
    public string Mode => "邀请码模式";
    public bool HasCredentials => !string.IsNullOrWhiteSpace(credentials.Load());
    public Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken cancellationToken = default)
    {
        var refresh = credentials.Load();
        return string.IsNullOrWhiteSpace(refresh)
            ? Task.FromResult(new AuthResponse<SessionResponse>(AuthResult.InvalidToken))
            : auth.SessionAsync(refresh, cancellationToken);
    }

    public async Task<AuthResponse<RedeemResponse>> RedeemAsync(string code, DeviceInfo device)
    {
        var response = await auth.RedeemAsync(new RedeemRequest { Code = code, Device = device, RefreshToken = credentials.Load() });
        if (response.Result == AuthResult.Ok && response.Value is not null) credentials.Save(response.Value.RefreshToken);
        return response;
    }
}

public sealed class PairingSessionSource : ISessionSource
{
    private readonly PairingFile pairing;
    public string Mode => "自用模式";
    public PairingSessionSource(PairingFile pairing, RedactingLog? log = null)
    {
        this.pairing = pairing;
        pairing.RegisterSecrets(log ?? new RedactingLog(NullLog.Instance));
    }
    public Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new AuthResponse<SessionResponse>(AuthResult.Ok, new SessionResponse
        {
            SessionToken = "", SessionExpiresAt = DateTimeOffset.MaxValue, AccountExpiresAt = DateTimeOffset.MaxValue,
            Node = pairing.Node, SingboxConfig = LocalConfigRenderer.Render(pairing.Node)
        }));
    }
}
