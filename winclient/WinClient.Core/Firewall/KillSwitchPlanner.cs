using System.Net;
using System.Net.Sockets;
using System.Text;

namespace WinClient.Core.Firewall;

public enum KillSwitchMode { Apply, Remove, Audit }
public abstract record FirewallAction;
public sealed record SetProfileDefault(string Profile, string Action) : FirewallAction;
public sealed record AddRule(string Name, string Direction, string Action, string? Program = null,
    string[]? RemoteAddress = null, string? Protocol = null, string? LocalPort = null,
    string? RemotePort = null, string? InterfaceAlias = null) : FirewallAction;
public sealed record RemoveRulesByPrefix(string Prefix) : FirewallAction;
public sealed record RestoreProfileDefault : FirewallAction;
public sealed record Audit : FirewallAction;

public static class KillSwitchPlanner
{
    public const string Prefix = "YuanC-KS-";
    public const string NodePrefix = Prefix + "Node-";
    public const string TunAlias = "YuanC-TUN";

    public static IReadOnlyList<FirewallAction> Plan(IReadOnlyList<IPAddress> nodeIps,
        string tunInterfaceName, string programPath, int hy2Port, KillSwitchMode mode, int realityPort = 443)
    {
        if (mode == KillSwitchMode.Remove) return [new RemoveRulesByPrefix(Prefix), new RestoreProfileDefault()];
        if (mode == KillSwitchMode.Audit) return [new Audit()];
        ArgumentException.ThrowIfNullOrWhiteSpace(tunInterfaceName);
        var actions = new List<FirewallAction>
        {
            new SetProfileDefault("Domain", "Block"),
            new SetProfileDefault("Private", "Block"),
            new SetProfileDefault("Public", "Block")
        };
        actions.AddRange(NodeRules(nodeIps, programPath, hy2Port, realityPort));
        actions.Add(new AddRule(Prefix + "Tun", "Outbound", "Allow", InterfaceAlias: tunInterfaceName));
        actions.Add(new AddRule(Prefix + "Loopback", "Outbound", "Allow", RemoteAddress: ["127.0.0.0/8", "::1"]));
        actions.Add(new AddRule(Prefix + "Dhcp", "Outbound", "Allow", Protocol: "UDP", LocalPort: "68", RemotePort: "67"));
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
        if (actions.OfType<SetProfileDefault>().Any())
        {
            script.AppendLine("[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($statePath)) | Out-Null");
            script.AppendLine("if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else {");
            script.AppendLine("  $profiles = @(Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction)");
            script.AppendLine("  if ($profiles.Count -ne 3) { throw '无法读取全部防火墙配置，未更改系统。' }");
            script.AppendLine("  $state = @{ applied = $false; profiles = @($profiles | ForEach-Object { @{ Name = [string]$_.Name; DefaultOutboundAction = [string]$_.DefaultOutboundAction } }) }; Write-State $state\n}");
        }
        foreach (var action in actions)
        {
            switch (action)
            {
                case SetProfileDefault setting:
                    if (setting.Profile is not ("Domain" or "Private" or "Public") || setting.Action != "Block")
                        throw new ArgumentException("无效的防火墙默认策略。");
                    script.AppendLine("Set-NetFirewallProfile -DefaultOutboundAction Block -Profile " + Quote(setting.Profile));
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
                    script.AppendLine("  foreach ($p in $state.profiles) { if ($p.Name -notin @('Domain','Private','Public') -or $p.DefaultOutboundAction -notin @('Allow','Block','NotConfigured')) { throw '防火墙恢复记录无效。' } }");
                    script.AppendLine("  foreach ($p in $state.profiles) { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction }");
                    script.AppendLine("  Remove-Item -LiteralPath $statePath\n} else { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow }");
                    break;
                case Audit:
                    script.AppendLine("[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($auditPath)) | Out-Null");
                    script.AppendLine("$audit = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow | Where-Object { $_.Name -notlike 'YuanC-KS-*' } | ForEach-Object { $r = $_; $app = $r | Get-NetFirewallApplicationFilter; [pscustomobject]@{ Name = $r.Name; Program = $app.Program } })");
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
