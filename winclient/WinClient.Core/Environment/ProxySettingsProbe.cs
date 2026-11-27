using Microsoft.Win32;
using System.Text.RegularExpressions;

namespace WinClient.Core.EnvironmentSupport;

/// <summary>一个账户（或整机策略）的代理设置原值；只用于判定，不写进任何明细。</summary>
public sealed record ProxyUserValues(int? ProxyEnable, string? ProxyServer, string? AutoConfigUrl,
    IReadOnlyDictionary<string, string?> Environment);

/// <summary>一次只读采集的结果；MachineWide 为 false 时 Machine 里的代理值不参与判定。</summary>
public sealed record ProxySnapshot(IReadOnlyList<ProxyUserValues> Users,
    IReadOnlyDictionary<string, string?> MachineEnvironment, bool MachineWide, ProxyUserValues? Machine);

/// <summary>只按固定词报告开着哪类代理设置，绝不带出地址、端口、账号或脚本网址。</summary>
public static class ProxySettings
{
    public static IReadOnlyList<string> Findings(ProxySnapshot snapshot)
    {
        var scopes = snapshot.MachineWide && snapshot.Machine is not null
            ? snapshot.Users.Append(snapshot.Machine).ToArray()
            : snapshot.Users.ToArray();
        var systemProxy = scopes.Any(value => value.ProxyEnable == 1 && !string.IsNullOrWhiteSpace(value.ProxyServer));
        var autoConfig = scopes.Any(value => !string.IsNullOrWhiteSpace(value.AutoConfigUrl));
        bool HasEnvironment(string name) => snapshot.Users
            .SelectMany(value => value.Environment)
            .Concat(snapshot.MachineEnvironment)
            .Any(pair => string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(pair.Value));
        var findings = new List<string>(5);
        if (systemProxy) findings.Add("系统代理");
        if (autoConfig) findings.Add("自动代理脚本");
        if (HasEnvironment("HTTP_PROXY")) findings.Add("环境变量 HTTP_PROXY");
        if (HasEnvironment("HTTPS_PROXY")) findings.Add("环境变量 HTTPS_PROXY");
        if (HasEnvironment("ALL_PROXY")) findings.Add("环境变量 ALL_PROXY");
        return findings;
    }
}

/// <summary>取不到代理设置时返回 null；实现不得抛异常、起子进程或写注册表。</summary>
public interface IProxySettingsProbe
{
    IReadOnlyList<string>? Snapshot();
}

/// <summary>只读注册表组出快照；单个键读不到按没有处理，整体出错返回 null。</summary>
public sealed class RegistryProxySettingsProbe : IProxySettingsProbe
{
    private const string UserInternetSettings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string MachineInternetSettings = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string MachineEnvironmentPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    private const string PolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    private static readonly Regex UserSid = new("^S-1-5-21-[0-9-]+$", RegexOptions.Compiled);

    public IReadOnlyList<string>? Snapshot()
    {
        try
        {
            var users = new List<ProxyUserValues>();
            foreach (var name in Registry.Users.GetSubKeyNames())
            {
                if (name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase) || !UserSid.IsMatch(name)) continue;
                try
                {
                    using var userKey = Registry.Users.OpenSubKey(name);
                    if (userKey is not null) users.Add(ReadScope(userKey, UserInternetSettings, "Environment"));
                }
                catch (Exception) { } // 单个账户读不到按没有处理。
            }
            var machineEnvironment = ReadEnvironment(Registry.LocalMachine, MachineEnvironmentPath);
            var machineWide = ReadProxySettingsPerUser() == 0;
            var machine = machineWide
                ? ReadScope(Registry.LocalMachine, MachineInternetSettings, MachineEnvironmentPath)
                : null;
            return ProxySettings.Findings(new ProxySnapshot(users, machineEnvironment, machineWide, machine));
        }
        catch (Exception) { return null; }
    }

    private static ProxyUserValues ReadScope(RegistryKey root, string internetPath, string environmentPath)
    {
        using var internet = root.OpenSubKey(internetPath);
        return new ProxyUserValues(
            internet?.GetValue("ProxyEnable") is int enable ? enable : null,
            internet?.GetValue("ProxyServer") as string,
            internet?.GetValue("AutoConfigURL") as string,
            ReadEnvironment(root, environmentPath));
    }

    private static IReadOnlyDictionary<string, string?> ReadEnvironment(RegistryKey root, string path)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var key = root.OpenSubKey(path);
            if (key is null) return values;
            foreach (var name in key.GetValueNames()) values[name] = key.GetValue(name)?.ToString();
        }
        catch (Exception) { }
        return values;
    }

    private static int? ReadProxySettingsPerUser()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PolicyPath);
            return key?.GetValue("ProxySettingsPerUser") is int value ? value : null;
        }
        catch (Exception) { return null; }
    }
}
