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
    string? RemotePort = null, string? InterfaceAlias = null,
    string? Service = null, string[]? LocalAddress = null) : FirewallAction;
public sealed record RemoveRulesByPrefix(string Prefix) : FirewallAction;
public sealed record RestoreProfileDefault : FirewallAction;
public sealed record RecoverFallback : FirewallAction;
public sealed record VerifyProfiles : FirewallAction;
public sealed record Audit : FirewallAction;
public sealed record Patrol(string[] ExpectedRules, bool EnforceDefaultBlock = true) : FirewallAction;
public sealed record RecordState(string Mode) : FirewallAction;
public sealed record EnableProfiles : FirewallAction;
public sealed record AddBlockRule(string Name, string Program, string[] LocalAddress) : FirewallAction;
public sealed record VerifyRules(string[] Names) : FirewallAction;

public static class KillSwitchPlanner
{
    public const string Prefix = "YuanC-KS-";
    public const string AppPrefix = Prefix + "App-";
    public static readonly string[] NonTunLocalAddresses = ["0.0.0.0-126.255.255.255", "128.0.0.0-172.19.0.0",
        "172.19.0.2-255.255.255.255", "::2-fdfe:dcba:9876::0", "fdfe:dcba:9876::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
    public static string[] AppRuleNames(int count) => Enumerable.Range(1, count).Select(i => AppPrefix + i).ToArray();

    public static IReadOnlyList<FirewallAction> PlanApps(IReadOnlyList<string> programs)
    {
        if (programs.Count is < 1 or > 32 || programs.Any(path => string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)))
            throw new ArgumentException("仅指定程序模式必须提供 1 到 32 个程序的绝对路径。");
        var names = AppRuleNames(programs.Count);
        var actions = new List<FirewallAction> { new RecordState("apps"), new EnableProfiles() };
        for (var i = 0; i < programs.Count; i++) actions.Add(new AddBlockRule(names[i], programs[i], NonTunLocalAddresses));
        actions.Add(new VerifyRules(names));
        actions.Add(new Audit());
        return actions.AsReadOnly();
    }
    public const string NodePrefix = Prefix + "Node-";
    public const string TunAlias = "YuanC-TUN";
    public const string TunAddress = "172.19.0.1";
    public static string DhcpProgram => Path.Combine(Environment.SystemDirectory, "svchost.exe");

    public static string[] ExpectedRuleNames(bool withAuth) =>
        [NodePrefix + "Tcp", NodePrefix + "Udp", .. (withAuth ? new[] { Prefix + "Auth" } : []),
            Prefix + "Tun", Prefix + "Loopback", Prefix + "Dhcp", Prefix + "Lan"];

    public static IReadOnlyList<FirewallAction> Plan(IReadOnlyList<IPAddress> nodeIps,
        string tunInterfaceName /* 接口保留并校验非空;隧道规则改按本地地址匹配,不再使用网卡名 */, string programPath, int hy2Port, KillSwitchMode mode, int realityPort = 443, AuthEndpoint? auth = null)
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
        actions.Add(new AddRule(Prefix + "Tun", "Outbound", "Allow", LocalAddress: [TunAddress]));
        actions.Add(new AddRule(Prefix + "Loopback", "Outbound", "Allow", RemoteAddress: ["127.0.0.0/8", "::1"]));
        actions.Add(new AddRule(Prefix + "Dhcp", "Outbound", "Allow", Program: DhcpProgram, Service: "Dhcp", RemoteAddress: ["255.255.255.255", "LocalSubnet"], Protocol: "UDP", LocalPort: "68", RemotePort: "67"));
        actions.Add(new AddRule(Prefix + "Lan", "Outbound", "Allow", RemoteAddress: ["LocalSubnet"]));
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
        var record = actions.OfType<RecordState>().SingleOrDefault();
        // 仅指定程序模式的审计仍查询允许规则，使用只读过滤；不生成任何 Allow 操作参数。
        var allowQuery = record is null
            ? "Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow | Where-Object { "
            : "Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound | Where-Object { [string]$_.Action -eq 'Allow' -and ";
        var script = new StringBuilder("$ErrorActionPreference = 'Stop'\n");
        script.AppendLine("$statePath = " + Quote(Path.GetFullPath(statePath)));
        script.AppendLine("$auditPath = " + Quote(Path.GetFullPath(auditPath)));
        script.AppendLine("function Write-State($value) { $temp = $statePath + '.tmp'; $value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8; Move-Item -LiteralPath $temp -Destination $statePath -Force }");
        if (actions.Any(action => action is DisableForeignAllowRules or Audit))
        {
            script.AppendLine("function Read-UnmanagedRules {");
            // Include disabled local rules too: ActiveStore may still contain a rule with the same name.
            script.AppendLine("  $persistentNames = @(Get-NetFirewallRule -PolicyStore PersistentStore | Select-Object -ExpandProperty Name)");
            script.AppendLine("  " + allowQuery + "$_.Name -notlike 'YuanC-KS-*' -and $persistentNames -notcontains $_.Name } | ForEach-Object { $r = $_; $app = $r | Get-NetFirewallApplicationFilter; [pscustomobject]@{ Name = $r.Name; Program = $app.Program } }");
            script.AppendLine("}");
        }
        if (actions.OfType<SetProfileDefault>().Any() || record is not null)
        {
            script.AppendLine("[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($statePath)) | Out-Null");
            script.AppendLine("if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else {");
            script.AppendLine("  $profiles = @(Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction,Enabled)");
            script.AppendLine("  if ($profiles.Count -ne 3) { throw '无法读取全部防火墙配置，未更改系统。' }");
            if (record is null)
                script.AppendLine("  $state = [pscustomobject]@{ applied = $false; profiles = @($profiles | ForEach-Object { @{ Name = [string]$_.Name; DefaultOutboundAction = [string]$_.DefaultOutboundAction; Enabled = [string]$_.Enabled } }) }; Write-State $state\n}");
            else
                script.AppendLine("  $state = [pscustomobject]@{ applied = $false; mode = " + Quote(record.Mode) + "; profiles = @($profiles | ForEach-Object { @{ Name = [string]$_.Name; DefaultOutboundAction = [string]$_.DefaultOutboundAction; Enabled = [string]$_.Enabled } }) }; Write-State $state\n}");
        }
        foreach (var action in actions)
        {
            switch (action)
            {
                case RecordState:
                    break; // 快照在所有修改动作之前写入。
                case EnableProfiles:
                    script.AppendLine("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True");
                    break;
                case AddBlockRule block:
                    if (!block.Name.StartsWith(AppPrefix, StringComparison.Ordinal) ||
                        string.IsNullOrWhiteSpace(block.Program) || !Path.IsPathFullyQualified(block.Program) || block.LocalAddress.Length == 0)
                        throw new ArgumentException("程序阻断规则必须使用本项目程序前缀、绝对路径和非空本地地址。");
                    script.AppendLine("Get-NetFirewallRule -Name " + Quote(block.Name) + " -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
                    script.AppendLine("New-NetFirewallRule -Name " + Quote(block.Name) + " -DisplayName " + Quote(block.Name)
                        + " -Direction Outbound -Action Block -Profile Any -Program " + Quote(block.Program)
                        + " -LocalAddress @(" + string.Join(",", block.LocalAddress.Select(Quote)) + ") | Out-Null");
                    break;
                case VerifyRules verify:
                    AppendVerifyRules(script, verify.Names);
                    break;
                case Patrol appsPatrol when !appsPatrol.EnforceDefaultBlock:
                    AppendAppsPatrol(script, appsPatrol.ExpectedRules);
                    break;
                case Patrol patrol:
                    script.AppendLine("$reenforced=@()");
                    // 管理命令失败先留存，仍检查服务和实际配置，防止把失效误报成普通查询失败。
                    script.AppendLine("$patrolErrors = @(); $newlyDisabled = @(); $state = $null");
                    script.AppendLine("$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors)");
                    script.AppendLine("foreach ($p in $profiles) {");
                    script.AppendLine("  if ([string]$p.Enabled -ne 'True' -or [string]$p.DefaultOutboundAction -ne 'Block') {");
                    script.AppendLine("    Set-NetFirewallProfile -Profile $p.Name -Enabled True -DefaultOutboundAction Block -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors | Out-Null");
                    script.AppendLine("    $reenforced += [string]$p.Name");
                    script.AppendLine("  }\n}");
                    script.AppendLine("if (Test-Path -LiteralPath $statePath) {");
                    script.AppendLine("  $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json");
                    script.AppendLine("  if ($null -eq $state.PSObject.Properties['disabledRules']) { $state | Add-Member -NotePropertyName disabledRules -NotePropertyValue @() }");
                    script.AppendLine("  if ($null -eq $state.PSObject.Properties['disableFailed']) { $state | Add-Member -NotePropertyName disableFailed -NotePropertyValue @() }");
                    script.AppendLine("  $foreignRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Direction Outbound -Action Allow -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors | Where-Object { $_.Name -notlike 'YuanC-KS-*' -and $state.disabledRules -notcontains $_.Name })");
                    script.AppendLine("  $state.disabledRules = @(@($state.disabledRules) + @($foreignRules.Name) | Where-Object { $null -ne $_ } | Sort-Object -Unique)");
                    // 必须先落恢复名单；停用中途失败也能在主动断开时恢复。
                    script.AppendLine("  Write-State $state");
                    script.AppendLine("  $disableFailed = @($state.disableFailed)");
                    script.AppendLine("  foreach ($rule in $foreignRules) {");
                    script.AppendLine("    $disableError = @()");
                    script.AppendLine("    try { $rule | Disable-NetFirewallRule -ErrorAction SilentlyContinue -ErrorVariable disableError | Out-Null } catch { $disableError = @($_) }");
                    script.AppendLine("    if ($disableError) { $disableFailed += $rule.Name; $patrolErrors += $disableError } else { $newlyDisabled += [string]$rule.Name }");
                    script.AppendLine("  }");
                    script.AppendLine("  $state.disableFailed = @($disableFailed | Where-Object { $null -ne $_ } | Sort-Object -Unique)");
                    script.AppendLine("  Write-State $state\n}");
                    script.AppendLine("$missing = @(@(" + string.Join(",", patrol.ExpectedRules.Select(Quote)) + ") | Where-Object { -not (Get-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue) })");
                    script.AppendLine("if ((Get-Service MpsSvc).Status -ne 'Running') { exit 3 }");
                    script.AppendLine("$effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors)");
                    script.AppendLine("$bad = @($effective | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultOutboundAction -ne 'Block' } | Select-Object -ExpandProperty Name)");
                    script.AppendLine("if ($effective.Count -ne 3) { $bad = @(@($bad) + @('Domain','Private','Public') | Sort-Object -Unique) }");
                    script.AppendLine("if ($bad.Count -gt 0) {");
                    script.AppendLine("  if ($null -ne $state) {");
                    script.AppendLine("    if ($null -eq $state.PSObject.Properties['verifyFailed']) { $state | Add-Member -NotePropertyName verifyFailed -NotePropertyValue @() }");
                    script.AppendLine("    $state.verifyFailed = @($bad); Write-State $state");
                    script.AppendLine("  }\n  exit 3\n}");
                    script.AppendLine("if ($patrolErrors.Count -gt 0) { throw '断网保护巡检失败,请联系管理员。' }");
                    script.AppendLine("ConvertTo-Json -Compress @{ reenforced=@($reenforced); newly_disabled=@($newlyDisabled); missing_rules=@($missing) }");
                    script.AppendLine("exit 0");
                    break;
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
                    AddArgument(script, "Service", rule.Service);
                    if (rule.LocalAddress is not null)
                        script.Append(" -LocalAddress @(").Append(string.Join(",", rule.LocalAddress.Select(Quote))).Append(')');
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
                    script.AppendLine("$foreignAllowRules = @(" + allowQuery + "$_.Name -notlike 'YuanC-KS-*' } | ForEach-Object { $r = $_; $app = $r | Get-NetFirewallApplicationFilter; [pscustomobject]@{ Name = $r.Name; Program = $app.Program } })");
                    script.AppendLine("$auditState = $null");
                    script.AppendLine("if (Test-Path -LiteralPath $statePath) { $auditState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }");
                    script.AppendLine("if ($null -ne $auditState -and $null -ne $auditState.PSObject.Properties['unmanagedRules']) { $unmanagedRules = @($auditState.unmanagedRules) } else { $unmanagedRules = @(Read-UnmanagedRules) }");
                    script.AppendLine("$audit = [pscustomobject]@{ foreign_allow_rules = @($foreignAllowRules); unmanaged_rules = @($unmanagedRules); generated_at = [DateTime]::UtcNow.ToString('o'); profiles_effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultOutboundAction) }");
                    script.AppendLine("ConvertTo-Json -InputObject $audit -Depth 5 | Set-Content -LiteralPath $auditPath -Encoding UTF8");
                    break;
                default: throw new ArgumentException("未知的防火墙操作。");
            }
        }
        if (actions.OfType<SetProfileDefault>().Any() || record is not null) script.AppendLine("$state.applied = $true; Write-State $state");
        return script.ToString();
    }

    private static void AppendVerifyRules(StringBuilder script, string[] names)
    {
        script.AppendLine("if ((Get-Service MpsSvc).Status -ne 'Running') { exit 3 }");
        script.AppendLine("if ($null -eq $state.PSObject.Properties['verifyFailed']) { $state | Add-Member -NotePropertyName verifyFailed -NotePropertyValue @() }");
        script.AppendLine("if ($null -eq $state.PSObject.Properties['verifiedAt']) { $state | Add-Member -NotePropertyName verifiedAt -NotePropertyValue $null }");
        script.AppendLine("$effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore)");
        script.AppendLine("$bad = @($effective | Where-Object { [string]$_.Enabled -ne 'True' } | Select-Object -ExpandProperty Name)");
        script.AppendLine("if ($effective.Count -ne 3) { $bad = @(@($bad) + @('Domain','Private','Public') | Sort-Object -Unique) }");
        script.AppendLine("if ($bad.Count -gt 0) { $state.verifyFailed = @($bad); Write-State $state; exit 3 }");
        AppendMissingAppRules(script, names);
        script.AppendLine("if ($missing.Count -gt 0) { $state.verifyFailed = @($missing); Write-State $state; exit 3 }");
        script.AppendLine("$state.verifiedAt = [DateTime]::UtcNow.ToString('o'); $state.verifyFailed = @(); Write-State $state");
    }

    private static void AppendMissingAppRules(StringBuilder script, string[] names)
    {
        script.AppendLine("$missing = @(@(" + string.Join(",", names.Select(Quote)) + ") | Where-Object { $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $_ -ErrorAction SilentlyContinue); $rules.Count -ne 1 -or @($rules | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.Action -ne 'Block' }).Count -gt 0 })");
    }

    private static void AppendAppsPatrol(StringBuilder script, string[] names)
    {
        script.AppendLine("$reenforced=@()");
        script.AppendLine("$patrolErrors = @(); $newlyDisabled = @(); $state = $null");
        script.AppendLine("$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors)");
        script.AppendLine("foreach ($p in $profiles) {");
        script.AppendLine("  if ([string]$p.Enabled -ne 'True') {");
        script.AppendLine("    Set-NetFirewallProfile -Profile $p.Name -Enabled True -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors | Out-Null");
        script.AppendLine("    $reenforced += [string]$p.Name");
        script.AppendLine("  }\n}");
        script.AppendLine("if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }");
        AppendMissingAppRules(script, names);
        script.AppendLine("if ((Get-Service MpsSvc).Status -ne 'Running') { exit 3 }");
        script.AppendLine("$effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +patrolErrors)");
        script.AppendLine("$bad = @($effective | Where-Object { [string]$_.Enabled -ne 'True' } | Select-Object -ExpandProperty Name)");
        script.AppendLine("if ($effective.Count -ne 3) { $bad = @(@($bad) + @('Domain','Private','Public') | Sort-Object -Unique) }");
        script.AppendLine("if ($bad.Count -gt 0) {");
        script.AppendLine("  if ($null -ne $state) {");
        script.AppendLine("    if ($null -eq $state.PSObject.Properties['verifyFailed']) { $state | Add-Member -NotePropertyName verifyFailed -NotePropertyValue @() }");
        script.AppendLine("    $state.verifyFailed = @($bad); Write-State $state");
        script.AppendLine("  }\n  exit 3\n}");
        script.AppendLine("if ($patrolErrors.Count -gt 0) { throw '断网保护巡检失败,请联系管理员。' }");
        script.AppendLine("ConvertTo-Json -Compress @{ reenforced=@($reenforced); newly_disabled=@($newlyDisabled); missing_rules=@($missing) }");
        script.AppendLine("exit 0");
    }

    private static void AddArgument(StringBuilder script, string name, string? value)
    {
        if (value is not null) script.Append(" -").Append(name).Append(' ').Append(Quote(value));
    }
    private static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
}
