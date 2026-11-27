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
    /// <summary>导出诊断；旧实现不覆写时返回空，服务端按「不支持的指令」应答。</summary>
    Task<string?> ReadDiagnosticsAsync(CancellationToken token = default) => Task.FromResult<string?>(null);
}
