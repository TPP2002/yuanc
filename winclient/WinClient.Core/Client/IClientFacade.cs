namespace WinClient.Core.Client;

public interface IClientFacade
{
    ClientSnapshot Snapshot { get; }
    event Action<ClientSnapshot>? Changed;
    Task ConnectAsync();
    Task DisconnectAsync();
    Task SetEnvironmentEnabledAsync(bool enabled);
    Task RedeemAsync(string code);
    Task ImportPairingAsync(string json);
    Task ClearPairingAsync();
    string? ReadAudit();
    string? ReadSelfCheck();
}
