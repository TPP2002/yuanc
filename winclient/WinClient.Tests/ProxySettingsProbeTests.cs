using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class ProxySettingsProbeTests
{
    private static readonly IReadOnlyDictionary<string, string?> NoEnvironment = new Dictionary<string, string?>();

    private static ProxyUserValues User(int? enable = null, string? server = null, string? auto = null,
        IReadOnlyDictionary<string, string?>? environment = null) =>
        new(enable, server, auto, environment ?? NoEnvironment);

    private static ProxySnapshot Snapshot(IReadOnlyList<ProxyUserValues>? users = null,
        IReadOnlyDictionary<string, string?>? machineEnvironment = null, bool machineWide = false,
        ProxyUserValues? machine = null) =>
        new(users ?? [], machineEnvironment ?? NoEnvironment, machineWide, machine);

    [Fact]
    public void NoSettingsGivesEmptyFindings() => Assert.Empty(ProxySettings.Findings(Snapshot()));

    [Fact]
    public void EnabledProxyWithServerIsReported()
    {
        Assert.Equal(new[] { "系统代理" }, ProxySettings.Findings(Snapshot([User(1, "10.1.2.3:8080")])));
        Assert.Empty(ProxySettings.Findings(Snapshot([User(1, "   ")])));
        Assert.Empty(ProxySettings.Findings(Snapshot([User(0, "10.1.2.3:8080")])));
    }

    [Fact]
    public void AutoConfigUrlIsReported() => Assert.Equal(new[] { "自动代理脚本" },
        ProxySettings.Findings(Snapshot([User(auto: "http://10.1.2.3/proxy.pac")])));

    [Fact]
    public void ProxyEnvironmentVariablesAreReportedCaseInsensitively()
    {
        var userEnvironment = new Dictionary<string, string?> { ["https_proxy"] = "http://10.1.2.3:8080" };
        var machineEnvironment = new Dictionary<string, string?> { ["All_Proxy"] = "socks5://10.1.2.3:1080" };
        Assert.Equal(new[] { "环境变量 HTTPS_PROXY", "环境变量 ALL_PROXY" },
            ProxySettings.Findings(Snapshot([User(environment: userEnvironment)], machineEnvironment)));

        var blank = new Dictionary<string, string?> { ["HTTP_PROXY"] = "  " };
        Assert.Empty(ProxySettings.Findings(Snapshot([User(environment: blank)])));

        var lookalike = new Dictionary<string, string?>
        {
            ["NO_PROXY"] = "10.1.2.3", ["MY_HTTP_PROXY_X"] = "http://10.1.2.3:8080"
        };
        Assert.Empty(ProxySettings.Findings(Snapshot([User(environment: lookalike)])));
    }

    [Fact]
    public void MachineWideProxyCountsOnlyWhenPolicyDisablesPerUser()
    {
        var machine = User(1, "10.1.2.3:8080");
        Assert.Empty(ProxySettings.Findings(Snapshot(machineWide: false, machine: machine)));
        Assert.Equal(new[] { "系统代理" }, ProxySettings.Findings(Snapshot(machineWide: true, machine: machine)));
    }

    [Fact]
    public void FindingsNeverContainValues()
    {
        var environment = new Dictionary<string, string?>
        {
            ["HTTP_PROXY"] = "user:secret@10.1.2.3:8080",
            ["HTTPS_PROXY"] = "user:secret@10.1.2.3:8080",
            ["ALL_PROXY"] = "user:secret@10.1.2.3:8080"
        };
        var findings = ProxySettings.Findings(Snapshot(
            [User(1, "user:secret@10.1.2.3:8080", "http://10.1.2.3/proxy.pac", environment)],
            environment, true, User(1, "user:secret@10.1.2.3:8080", "http://10.1.2.3/proxy.pac", environment)));
        Assert.NotEmpty(findings);
        foreach (var finding in findings)
            foreach (var secret in new[] { "10.1.2.3", "secret", "8080", "pac" })
                Assert.DoesNotContain(secret, finding);
    }

    [Fact]
    public void FindingsAreDeduplicatedAndOrdered()
    {
        var environment = new Dictionary<string, string?>
        {
            ["HTTP_PROXY"] = "http://10.1.2.3:8080",
            ["HTTPS_PROXY"] = "http://10.1.2.3:8080",
            ["ALL_PROXY"] = "socks5://10.1.2.3:1080"
        };
        var users = new List<ProxyUserValues>
        {
            User(1, "10.1.2.3:8080"),
            User(1, "10.1.2.4:8080", "http://10.1.2.3/proxy.pac", environment)
        };
        var findings = ProxySettings.Findings(new ProxySnapshot(users, environment, false, null));
        Assert.Equal(5, findings.Count);
        Assert.Equal(new[] { "系统代理", "自动代理脚本", "环境变量 HTTP_PROXY", "环境变量 HTTPS_PROXY", "环境变量 ALL_PROXY" },
            findings);
    }

    [Fact]
    public void ReadSystemDoesNotThrow()
    {
        var snapshot = new RegistryProxySettingsProbe().Snapshot();
        Assert.True(snapshot is null || snapshot.Count >= 0);
    }
}
