using System.ComponentModel;
using System.Text.Json;
using WinClient.Core.Firewall;

namespace WinClient.Core.Diagnostics;

public sealed record NetworkStateResult(string? Json, string? Error);

/// <summary>只读查询路由与 DNS 现状；脚本不改任何系统设置，只读取两个存储里的路由、网卡、DNS 与内核进程。</summary>
public static class NetworkStateProbe
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);
    public const string TimedOut = "路由与 DNS 现状没有读到：超过时限没有返回。";
    public const string Failed = "路由与 DNS 现状没有读到：查询命令没有成功。";

    public const string Script =
        "$ErrorActionPreference = 'Stop'\n" +
        "$ProgressPreference = 'SilentlyContinue'\n" +
        "$lo = [System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex\n" +
        "function Read-Routes($store) { try { @(Get-NetRoute -PolicyStore $store -ErrorAction SilentlyContinue | Where-Object { [string]$_.DestinationPrefix -match '/[0-2]$' } | ForEach-Object { [ordered]@{ prefix = [string]$_.DestinationPrefix; next_hop = [string]$_.NextHop; alias = [string]$_.InterfaceAlias; index = [int]$_.InterfaceIndex; metric = [int]$_.RouteMetric; loopback = ([int]$_.InterfaceIndex -eq $lo) } }) } catch { @() } }\n" +
        "$interfaces = try { @(Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; index = [int]$_.ifIndex; family = [string]$_.AddressFamily; metric = [int]$_.InterfaceMetric; state = [string]$_.ConnectionState; dhcp = [string]$_.Dhcp } }) } catch { @() }\n" +
        "$dns = try { @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { @($_.ServerAddresses).Count -gt 0 } | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; family = $(if ([int]$_.AddressFamily -eq 23) { 'IPv6' } else { 'IPv4' }); servers = @($_.ServerAddresses | ForEach-Object { [string]$_ }) } }) } catch { @() }\n" +
        "$kernel = try { @(Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ id = [int]$_.Id; started = try { $_.StartTime.ToUniversalTime().ToString('o') } catch { '' }; path = try { [string]$_.Path } catch { '' } } }) } catch { @() }\n" +
        "$result = [ordered]@{ loopback_index = $lo; routes_active = @(Read-Routes 'ActiveStore'); routes_persistent = @(Read-Routes 'PersistentStore'); interfaces = @($interfaces); dns = @($dns); kernel_processes = @($kernel) }\n" +
        "ConvertTo-Json -InputObject $result -Depth 5 -Compress";

    public static async Task<NetworkStateResult> RunAsync(ICommandRunner runner, TimeSpan? timeout = null, CancellationToken token = default)
    {
        using var source = CancellationTokenSource.CreateLinkedTokenSource(token);
        source.CancelAfter(timeout ?? DefaultTimeout);
        CommandResult result;
        try
        {
            result = await runner.RunAsync(KillSwitchApplier.CreateStartInfo(Script), source.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // 只有本方法的计时器到点才算超时；外部令牌取消照旧透出。
            if (token.IsCancellationRequested) throw;
            return new(null, TimedOut);
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException)
        {
            return new(null, Failed);
        }
        if (result.ExitCode != 0) return new(null, Failed);
        var last = result.Output.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .LastOrDefault(line => line.Trim().Length > 0)?.Trim();
        if (last is null) return new(null, Failed);
        try
        {
            using var document = JsonDocument.Parse(last);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return new(null, Failed);
        }
        catch (JsonException)
        {
            return new(null, Failed);
        }
        return new(last, null);
    }
}
