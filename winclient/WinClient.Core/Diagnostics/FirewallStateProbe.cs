using System.ComponentModel;
using System.Text.Json;
using WinClient.Core.Firewall;

namespace WinClient.Core.Diagnostics;

public sealed record FirewallStateResult(string? Json, string? Error);

/// <summary>只读查询系统防火墙现状；脚本不改任何系统设置。</summary>
public static class FirewallStateProbe
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);
    public const string TimedOut = "系统防火墙现状没有读到：超过时限没有返回。";
    public const string Failed = "系统防火墙现状没有读到：查询命令没有成功。";

    public const string Script =
        "$ErrorActionPreference = 'Stop'\n" +
        "$ProgressPreference = 'SilentlyContinue'\n" +
        "function Read-Profiles($store) { try { @(Get-NetFirewallProfile -PolicyStore $store | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; default_outbound = [string]$_.DefaultOutboundAction; default_inbound = [string]$_.DefaultInboundAction } }) } catch { @() } }\n" +
        "$service = try { [string](Get-Service -Name MpsSvc).Status } catch { 'unknown' }\n" +
        "$own = try { @(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'YuanC-KS-*' -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; action = [string]$_.Action; direction = [string]$_.Direction } }) } catch { @() }\n" +
        "$outbound = try { @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -ErrorAction SilentlyContinue) } catch { @() }\n" +
        "$result = [ordered]@{ service = $service; profiles_local = @(Read-Profiles 'PersistentStore'); profiles_effective = @(Read-Profiles 'ActiveStore'); own_rules = @($own); outbound_rules_total = $outbound.Count; outbound_rules_enabled = @($outbound | Where-Object { [string]$_.Enabled -eq 'True' }).Count; outbound_allow_enabled = @($outbound | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Allow' }).Count }\n" +
        "ConvertTo-Json -InputObject $result -Depth 5 -Compress";

    public static async Task<FirewallStateResult> RunAsync(ICommandRunner runner, TimeSpan? timeout = null, CancellationToken token = default)
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
