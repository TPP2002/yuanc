using System.Net;
using System.Net.Sockets;
using System.Text;

namespace WinClient.Core.Firewall;

public enum KillSwitchMode { Apply, Remove, Audit }
public sealed record AuthEndpoint(IPAddress Address, int Port, string Program);
public abstract record FirewallAction;
public sealed record SetProfileDefault(string Profile, string Action) : FirewallAction;
public sealed record DisableForeignAllowRules : FirewallAction;
public sealed record AddRule(string Name, string Direction, string Action, string? Program = null,
    string[]? RemoteAddress = null, string? Protocol = null, string? LocalPort = null,
    string? RemotePort = null, string? InterfaceAlias = null) : FirewallAction;
public sealed record RemoveRulesByPrefix(string Prefix) : FirewallAction;
public sealed record RestoreProfileDefault : FirewallAction;
public sealed record RecoverFallback : FirewallAction;
public sealed record VerifyProfiles : FirewallAction;
public sealed record Audit : FirewallAction;

public static class KillSwitchPlanner
{
    public const string Prefix = "YuanC-KS-";
    public const string NodePrefix = Prefix + "Node-";
    public const string TunAlias = "YuanC-TUN";

    public static IReadOnlyList<FirewallAction> Plan(IReadOnlyList<IPAddress> nodeIps,
        string tunInterfaceName, string programPath, int hy2Port, KillSwitchMode mode, int realityPort = 443, AuthEndpoint? auth = null)
    {
        if (mode == KillSwitchMode.Remove) return [new RemoveRulesByPrefix(Prefix), new RestoreProfileDefault()];
        if (mode == KillSwitchMode.Audit) return [new Audit()];
        ArgumentException.ThrowIfNullOrWhiteSpace(tunInterfaceName);
        var actions = new List<FirewallAction>
        {
            new SetProfileDefault("Domain", "Block"),
            new SetProfileDefault("Private", "Block"),
            new SetProfileDefault("Public", "Block"),
            new DisableForeignAllowRules()
        };
        actions.AddRange(NodeRules(nodeIps, programPath, hy2Port, realityPort));
        if (auth is not null)
        {
            if (auth.Address is null || auth.Address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("鉴权服务器必须是 IPv4 数字地址。", nameof(auth));
            if (auth.Port is < 1 or > 65535)
                throw new ArgumentException("鉴权服务器端口必须在 1 到 65535 之间。", nameof(auth));
            if (string.IsNullOrWhiteSpace(auth.Program) || !Path.IsPathFullyQualified(auth.Program))
                throw new ArgumentException("后台服务程序必须是绝对路径。", nameof(auth));
            actions.Add(new AddRule(Prefix + "Auth", "Outbound", "Allow", Program: auth.Program,
                RemoteAddress: [auth.Address.ToString()], Protocol: "TCP",
                RemotePort: auth.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
        actions.Add(new AddRule(Prefix + "Tun", "Outbound", "Allow", InterfaceAlias: tunInterfaceName));
        actions.Add(new AddRule(Prefix + "Loopback", "Outbound", "Allow", RemoteAddress: ["127.0.0.0/8", "::1"]));
        actions.Add(new AddRule(Prefix + "Dhcp", "Outbound", "Allow", Protocol: "UDP", LocalPort: "68", RemotePort: "67"));
        actions.Add(new VerifyProfiles());
        actions.Add(new Audit());
        return actions.AsReadOnly();
    }

    public static IReadOnlyList<FirewallAction> UpdateNode(IReadOnlyList<IPAddress> newIps, string programPath, int hy2Port, int realityPort = 443)
        => new FirewallAction[] { new RemoveRulesByPrefix(NodePrefix) }.Concat(NodeRules(newIps, programPath, hy2Port, realityPort)).ToArray();

    private static IEnumerable<FirewallAction> NodeRules(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        if (!Path.IsPathFullyQualified(program)) throw new ArgumentException("连接内核路径必须是绝对路径。", nameof(program));
        if (ips.Count == 0 || ips.Any(ip => ip.AddressFamily != AddressFamily.InterNetwork))
            throw new ArgumentException("节点必须提供至少一个 IPv4 地址。", nameof(ips));
        if (hy2Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(hy2Port));
        if (realityPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(realityPort));
        var addresses = ips.Select(ip => ip.ToString()).Distinct().Order().ToArray();
        return [new AddRule(NodePrefix + "Tcp", "Outbound", "Allow", program, addresses, "TCP", RemotePort: realityPort.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new AddRule(NodePrefix + "Udp", "Outbound", "Allow", program, addresses, "UDP", RemotePort: hy2Port.ToString(System.Globalization.CultureInfo.InvariantCulture))];
    }

    public static string ToPowerShellScript(IReadOnlyList<FirewallAction> actions, string statePath, string auditPath)
    {
        var script = new StringBuilder("$ErrorActionPreference = 'Stop'\n");
        script.AppendLine("$statePath = " + Quote(Path.GetFullPath(statePath)));
        script.AppendLine("$auditPath = " + Quote(Path.GetFullPath(auditPath)));
        script.AppendLine("function Write-State($value) { $temp = $statePath + '.tmp'; $value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8; Move-Item -LiteralPath $temp -Destination $statePath -Force }");
        if (actions.Any(action => action is DisableForeignAllowRules or Audit))
        {
            script.AppendLine("function Read-UnmanagedRules {");
            // Include disabled local rules too: ActiveStore may still contain a rule with the same name.
            script.AppendLine("  $persistentNames = @(Get-NetFirewallRule -PolicyStore PersistentStore | Select-Object -ExpandProperty Name)");
            script.AppendLine("  Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow | Where-Object { $_.Name -notlike 'YuanC-KS-*' -and $persistentNames -notcontains $_.Name } | ForEach-Object { $r = $_; $app = $r | Get-NetFirewallApplicationFilter; [pscustomobject]@{ Name = $r.Name; Program = $app.Program } }");
            script.AppendLine("}");
        }
        if (actions.OfType<SetProfileDefault>().Any())
        {
            script.AppendLine("[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($statePath)) | Out-Null");
            script.AppendLine("if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else {");
            script.AppendLine("  $profiles = @(Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction,Enabled)");
            script.AppendLine("  if ($profiles.Count -ne 3) { throw '无法读取全部防火墙配置，未更改系统。' }");
            script.AppendLine("  $state = [pscustomobject]@{ applied = $false; profiles = @($profiles | ForEach-Object { @{ Name = [string]$_.Name; DefaultOutboundAction = [string]$_.DefaultOutboundAction; Enabled = [string]$_.Enabled } }) }; Write-State $state\n}");
        }
        foreach (var action in actions)
        {
            switch (action)
            {
                case SetProfileDefault setting:
                    if (setting.Profile is not ("Domain" or "Private" or "Public") || setting.Action != "Block")
                        throw new ArgumentException("无效的防火墙默认策略。");
                    script.AppendLine("Set-NetFirewallProfile -Enabled True -DefaultOutboundAction Block -Profile " + Quote(setting.Profile));
                    break;
                case DisableForeignAllowRules:
                    script.AppendLine("$foreignRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Direction Outbound -Action Allow | Where-Object { $_.Name -notlike 'YuanC-KS-*' })");
                    // ConvertFrom-Json returns a PSCustomObject; add fields for legacy snapshots before assigning.
                    script.AppendLine("if ($null -eq $state.PSObject.Properties['disabledRules']) { $state | Add-Member -NotePropertyName disabledRules -NotePropertyValue @() }");
                    script.AppendLine("if ($null -eq $state.PSObject.Properties['disableFailed']) { $state | Add-Member -NotePropertyName disableFailed -NotePropertyValue @() }");
                    script.AppendLine("if ($null -eq $state.PSObject.Properties['unmanagedRules']) { $state | Add-Member -NotePropertyName unmanagedRules -NotePropertyValue @() }");
                    script.AppendLine("$state.disabledRules = @(@($state.disabledRules) + @($foreignRules.Name) | Where-Object { $null -ne $_ } | Sort-Object -Unique)");
                    script.AppendLine("$state.unmanagedRules = @(Read-UnmanagedRules)");
                    script.AppendLine("Write-State $state");
                    script.AppendLine("$disableFailed = @($state.disableFailed)");
                    script.AppendLine("foreach ($rule in $foreignRules) {");
                    script.AppendLine("  $disableError = @()");
                    script.AppendLine("  try { $rule | Disable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable disableError } catch { $disableError = @($_) }");
                    script.AppendLine("  if ($disableError) { $disableFailed += $rule.Name }");
                    script.AppendLine("}");
                    script.AppendLine("$state.disableFailed = @($disableFailed | Where-Object { $null -ne $_ } | Sort-Object -Unique)");
                    script.AppendLine("Write-State $state");
                    break;
                case AddRule rule:
                    if (!rule.Name.StartsWith(Prefix, StringComparison.Ordinal) || rule.Direction != "Outbound" || rule.Action != "Allow")
                        throw new ArgumentException("只允许创建本项目的出站放行规则。");
                    script.AppendLine("Get-NetFirewallRule -Name " + Quote(rule.Name) + " -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
                    script.Append("New-NetFirewallRule -Name ").Append(Quote(rule.Name))
                        .Append(" -DisplayName ").Append(Quote(rule.Name)).Append(" -Direction Outbound -Action Allow -Profile Any");
                    AddArgument(script, "Program", rule.Program);
                    if (rule.RemoteAddress is not null)
                        script.Append(" -RemoteAddress @(").Append(string.Join(",", rule.RemoteAddress.Select(Quote))).Append(')');
                    AddArgument(script, "Protocol", rule.Protocol);
                    AddArgument(script, "LocalPort", rule.LocalPort);
                    AddArgument(script, "RemotePort", rule.RemotePort);
                    AddArgument(script, "InterfaceAlias", rule.InterfaceAlias);
                    script.AppendLine(" | Out-Null");
                    break;
                case RemoveRulesByPrefix remove:
                    if (remove.Prefix is not (Prefix or NodePrefix)) throw new ArgumentException("禁止删除非本项目规则。");
                    script.AppendLine("Get-NetFirewallRule -Name " + Quote(remove.Prefix + "*") + " -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
                    break;
                case RestoreProfileDefault:
                    script.AppendLine("if (Test-Path -LiteralPath $statePath) {");
                    script.AppendLine("  $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json");
                    script.AppendLine("  if (@($state.profiles).Count -ne 3) { throw '防火墙恢复记录不完整，需人工处理。' }");
                    script.AppendLine("  foreach ($p in $state.profiles) { if ($p.Name -notin @('Domain','Private','Public') -or $p.DefaultOutboundAction -notin @('Allow','Block','NotConfigured') -or ($null -ne $p.PSObject.Properties['Enabled'] -and $p.Enabled -notin @('True','False'))) { throw '防火墙恢复记录无效。' } }");
                    script.AppendLine("  $restoreFailed = @()");
                    script.AppendLine("  if ($null -ne $state.disabledRules) {");
                    script.AppendLine("    foreach ($name in @($state.disabledRules)) {");
                    script.AppendLine("      $enableError = @()");
                    script.AppendLine("      try { Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $name } | Enable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable enableError } catch { $enableError = @($_) }");
                    script.AppendLine("      if ($enableError) { $restoreFailed += $name }");
                    script.AppendLine("    }\n  }");
                    script.AppendLine("  foreach ($p in $state.profiles) { if ($null -ne $p.PSObject.Properties['Enabled']) { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction } else { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction } }");
                    script.AppendLine("  if ($restoreFailed.Count -gt 0) { throw '部分防火墙规则恢复失败，恢复记录已保留，请联系管理员。' }");
                    script.AppendLine("  Remove-Item -LiteralPath $statePath\n} else { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow }");
                    break;
                case RecoverFallback:
                    script.AppendLine("$archived = $null; $state = $null");
                    script.AppendLine("$runDirectory = [IO.Path]::GetDirectoryName($statePath)");
                    script.AppendLine("if (Test-Path -LiteralPath $statePath) {");
                    script.AppendLine("  Get-ChildItem -LiteralPath $runDirectory -Filter 'killswitch-state.failed-*.json' -File | Sort-Object Name -Descending | Select-Object -Skip 4 | ForEach-Object { Remove-Item -LiteralPath $_.FullName -ErrorAction Stop }");
                    script.AppendLine("  $archived = 'killswitch-state.failed-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '.json'");
                    script.AppendLine("  $archivePath = Join-Path $runDirectory $archived");
                    script.AppendLine("  Copy-Item -LiteralPath $statePath -Destination $archivePath -ErrorAction Stop");
                    script.AppendLine("  try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop } catch { $state = $null }");
                    script.AppendLine("}");
                    script.AppendLine("$recordValid = $null -ne $state -and @($state.profiles).Count -eq 3");
                    script.AppendLine("if ($recordValid) {");
                    script.AppendLine("  foreach ($p in $state.profiles) { if ($p.Name -notin @('Domain','Private','Public') -or $p.DefaultOutboundAction -notin @('Allow','Block','NotConfigured') -or ($null -ne $p.PSObject.Properties['Enabled'] -and $p.Enabled -notin @('True','False'))) { $recordValid = $false } }");
                    script.AppendLine("  if (@($state.profiles.Name | Sort-Object -Unique).Count -ne 3) { $recordValid = $false }");
                    script.AppendLine("}");
                    script.AppendLine("if ($recordValid) {");
                    script.AppendLine("  foreach ($p in $state.profiles) { if ($null -ne $p.PSObject.Properties['Enabled']) { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction } else { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction } }");
                    script.AppendLine("  $profilesApplied = 'recorded'");
                    script.AppendLine("} else {");
                    script.AppendLine("  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow");
                    script.AppendLine("  $profilesApplied = 'windows_default'");
                    script.AppendLine("}");
                    script.AppendLine("$notEnabled = @()");
                    script.AppendLine("if ($null -ne $state.disabledRules) {");
                    script.AppendLine("  foreach ($name in @($state.disabledRules)) {");
                    script.AppendLine("    $enableError = @()");
                    script.AppendLine("    try { Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue -ErrorVariable enableError | Where-Object { $_.Name -eq $name -and $_.Direction -eq 'Outbound' } | Enable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable +enableError } catch { $enableError = @($_) }");
                    script.AppendLine("    if ($enableError) { $notEnabled += $name }");
                    script.AppendLine("  }");
                    script.AppendLine("}");
                    script.AppendLine("Get-NetFirewallRule -Name " + Quote(Prefix + "*") + " -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
                    script.AppendLine("$recoveryPath = Join-Path $runDirectory 'killswitch-recovery.json'");
                    script.AppendLine("$recovery = [pscustomobject]@{ at = [DateTime]::UtcNow.ToString('o'); archived = $archived; record_valid = $recordValid; profiles_applied = $profilesApplied; rules_not_enabled = @($notEnabled) }");
                    script.AppendLine("$recoveryTemp = $recoveryPath + '.tmp'");
                    script.AppendLine("$recovery | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recoveryTemp -Encoding UTF8");
                    script.AppendLine("Move-Item -LiteralPath $recoveryTemp -Destination $recoveryPath -Force");
                    script.AppendLine("if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath -ErrorAction Stop }");
                    script.AppendLine("exit 0");
                    break;
                case VerifyProfiles:
                    script.AppendLine("$effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultOutboundAction)");
                    script.AppendLine("$bad = @($effective | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultOutboundAction -ne 'Block' } | Select-Object -ExpandProperty Name)");
                    script.AppendLine("if ($effective.Count -ne 3) { $bad = @(@($bad) + @('Domain','Private','Public') | Sort-Object -Unique) }");
                    script.AppendLine("if ($null -eq $state.PSObject.Properties['verifyFailed']) { $state | Add-Member -NotePropertyName verifyFailed -NotePropertyValue @() }");
                    script.AppendLine("if ($null -eq $state.PSObject.Properties['verifiedAt']) { $state | Add-Member -NotePropertyName verifiedAt -NotePropertyValue $null }");
                    script.AppendLine("$state.verifiedAt = [DateTime]::UtcNow.ToString('o')");
                    script.AppendLine("if ($bad.Count -gt 0) { $state.verifyFailed = @($bad); Write-State $state; exit 3 }");
                    script.AppendLine("$state.verifyFailed = @(); Write-State $state");
                    break;
                case Audit:
                    script.AppendLine("[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($auditPath)) | Out-Null");
                    script.AppendLine("$foreignAllowRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow | Where-Object { $_.Name -notlike 'YuanC-KS-*' } | ForEach-Object { $r = $_; $app = $r | Get-NetFirewallApplicationFilter; [pscustomobject]@{ Name = $r.Name; Program = $app.Program } })");
                    script.AppendLine("$auditState = $null");
                    script.AppendLine("if (Test-Path -LiteralPath $statePath) { $auditState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }");
                    script.AppendLine("if ($null -ne $auditState -and $null -ne $auditState.PSObject.Properties['unmanagedRules']) { $unmanagedRules = @($auditState.unmanagedRules) } else { $unmanagedRules = @(Read-UnmanagedRules) }");
                    script.AppendLine("$audit = [pscustomobject]@{ foreign_allow_rules = @($foreignAllowRules); unmanaged_rules = @($unmanagedRules); generated_at = [DateTime]::UtcNow.ToString('o'); profiles_effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultOutboundAction) }");
                    script.AppendLine("ConvertTo-Json -InputObject $audit -Depth 5 | Set-Content -LiteralPath $auditPath -Encoding UTF8");
                    break;
                default: throw new ArgumentException("未知的防火墙操作。");
            }
        }
        if (actions.OfType<SetProfileDefault>().Any()) script.AppendLine("$state.applied = $true; Write-State $state");
        return script.ToString();
    }

    private static void AddArgument(StringBuilder script, string name, string? value)
    {
        if (value is not null) script.Append(" -").Append(name).Append(' ').Append(Quote(value));
    }
    private static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
}
