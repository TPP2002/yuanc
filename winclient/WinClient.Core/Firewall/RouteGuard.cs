namespace WinClient.Core.Firewall;

public interface IRouteGuard
{
    Task InstallAsync(CancellationToken token);
    Task RemoveAsync(CancellationToken token);
    Task<bool> IsInstalledAsync(CancellationToken token);
}

public sealed class RouteGuardException(string message) : InvalidOperationException(message);

/// <summary>回环兜底只处理 IPv4；只凭前缀、回环接口及专属跃点识别本产品路由。</summary>
public sealed class RouteGuard : IRouteGuard
{
    public const int Metric = 9473;
    public static readonly string[] Prefixes = ["0.0.0.0/1", "128.0.0.0/1"];
    public const string MissingMarker = "YuanC-Route";
    public static readonly string[] TunRoutes = ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2",
        "::/2", "4000::/2", "8000::/2", "c000::/2"];
    private readonly ICommandRunner runner;
    private readonly string[] prefixes;

    public RouteGuard(ICommandRunner? runner = null) : this(runner, Prefixes) { }
    internal RouteGuard(ICommandRunner? runner, IReadOnlyList<string> prefixes)
    {
        this.runner = runner ?? new CommandRunner();
        this.prefixes = prefixes.ToArray();
    }

    private string Setup => "$ErrorActionPreference = 'Stop'\n" +
        "$lo = [System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex\n" +
        "$prefixes = @(" + string.Join(",", prefixes.Select(p => "'" + p.Replace("'", "''", StringComparison.Ordinal) + "'")) + ")\n";

    public async Task InstallAsync(CancellationToken token)
    {
        await RunAsync(Setup + $$"""
            try {
                $own = { param($store) @(Get-NetRoute -PolicyStore $store | Where-Object {
                    $_.DestinationPrefix -eq $p -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq {{Metric}} }) }
                foreach ($p in $prefixes) {
                    if ((& $own 'ActiveStore').Count -gt 0 -and (& $own 'PersistentStore').Count -gt 0) { continue }
                    # New-NetRoute 不接受单写 PersistentStore(真机报参数无效):缺一处就删掉本产品的残留,再不带 -PolicyStore 同时写入两处。
                    foreach ($store in @('ActiveStore','PersistentStore')) { & $own $store | Remove-NetRoute -Confirm:$false | Out-Null }
                    New-NetRoute -DestinationPrefix $p -InterfaceIndex $lo -NextHop 0.0.0.0 -RouteMetric {{Metric}} | Out-Null
                }
                foreach ($p in $prefixes) {
                    if ((& $own 'ActiveStore').Count -eq 0 -or (& $own 'PersistentStore').Count -eq 0) { exit 1 }
                }
                exit 0
            } catch { exit 1 }
            """, token).ConfigureAwait(false);
    }

    public async Task RemoveAsync(CancellationToken token)
    {
        await RunAsync(Setup + $$"""
            try {
                foreach ($store in @('ActiveStore','PersistentStore')) {
                    Get-NetRoute -PolicyStore $store | Where-Object {
                        $prefixes -contains $_.DestinationPrefix -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq {{Metric}}
                    } | Remove-NetRoute -Confirm:$false | Out-Null
                }
                foreach ($store in @('ActiveStore','PersistentStore')) {
                    if (@(Get-NetRoute -PolicyStore $store | Where-Object {
                        $prefixes -contains $_.DestinationPrefix -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq {{Metric}} }).Count -ne 0) { exit 1 }
                }
                exit 0
            } catch { exit 1 }
            """, token).ConfigureAwait(false);
    }

    public async Task<bool> IsInstalledAsync(CancellationToken token)
    {
        var output = await RunAsync(Setup + $$"""
            try {
                foreach ($p in $prefixes) {
                    if (@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
                        $_.DestinationPrefix -eq $p -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq {{Metric}} }).Count -eq 0) {
                        Write-Output 0
                        exit 0
                    }
                }
                Write-Output 1
                exit 0
            } catch { exit 1 }
            """, token).ConfigureAwait(false);
        return output.Trim() switch
        {
            "1" => true,
            "0" => false,
            _ => throw new RouteGuardException("无法核验兜底路由，请联系管理员。")
        };
    }

    private async Task<string> RunAsync(string script, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        CommandResult result;
        try { result = await runner.RunAsync(KillSwitchApplier.CreateStartInfo(script), timeout.Token).ConfigureAwait(false); }
        catch (Exception) { throw new RouteGuardException("兜底路由操作失败或超时，请联系管理员。"); }
        if (result.ExitCode != 0) throw new RouteGuardException("兜底路由操作失败，请联系管理员。");
        return result.Output;
    }
}
