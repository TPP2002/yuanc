namespace WinClient.Core.Client;

public interface IClientFacade
{
    ClientSnapshot Snapshot { get; }
    event Action<ClientSnapshot>? Changed;
    Task ConnectAsync();
    Task DisconnectAsync();
    Task SetRoutingAsync(string mode, IReadOnlyList<string> apps);
    Task SetEnvironmentEnabledAsync(bool enabled);
    Task RestoreEnvironmentAsync();
    Task RedeemAsync(string code);
    Task ImportPairingAsync(string json);
    Task ClearPairingAsync();
    string? ReadAudit();
    string? ReadSelfCheck();
}
