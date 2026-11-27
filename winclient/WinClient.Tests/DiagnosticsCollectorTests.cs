using System.Text;
using System.Text.Json.Nodes;
using WinClient.Core.Client;
using WinClient.Core.Diagnostics;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

public class DiagnosticsCollectorTests
{
    private static DiagnosticsSources Sources(TempDirectory directory,
        Func<ClientSnapshot>? snapshot = null, Func<IReadOnlyList<string>>? wfp = null,
        Func<IReadOnlyList<AdapterInfo>?>? adapters = null,
        Func<CancellationToken, Task<FirewallStateResult>>? firewall = null,
        Func<string?>? audit = null, Func<string?>? selfCheck = null) => new()
        {
            RunDirectory = directory.Path,
            Snapshot = snapshot ?? (() => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false)),
            Version = "0.1.2",
            WfpFilterNames = wfp,
            Adapters = adapters,
            Firewall = firewall,
            Audit = audit,
            SelfCheck = selfCheck,
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };

    private static JsonObject Parse(string text) => JsonNode.Parse(text)!.AsObject();

    [Fact]
    public async Task CollectsAllSectionsAsValidJson()
    {
        using var directory = new TempDirectory();
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)));
        Assert.Equal(new[] { "schema", "collected_at", "version", "test_build", "system", "snapshot", "desired",
            "killswitch", "wfp_filters", "adapters", "firewall", "firewall_error", "logs", "firewall_audit",
            "self_check", "omitted", "errors" }, root.Select(pair => pair.Key));
    }

    [Fact]
    public async Task SnapshotOmitsExitIpAndKeepsOnlyAppFileNames()
    {
        using var directory = new TempDirectory();
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            snapshot: () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false)
            {
                ExitIp = "8.8.8.8",
                RoutingApps = [@"C:\Users\alice\App\chrome.exe"]
            })));
        var text = root.ToJsonString();
        Assert.DoesNotContain("8.8.8.8", text);
        Assert.DoesNotContain("alice", text);
        Assert.Equal(new[] { "chrome.exe" },
            root["snapshot"]!["routing_apps"]!.AsArray().Select(node => node!.GetValue<string>()));
    }

    [Fact]
    public async Task FailingSourceIsRecordedAndOthersSurvive()
    {
        using var directory = new TempDirectory();
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            wfp: () => throw new InvalidOperationException("boom"))));
        Assert.Null(root["wfp_filters"]);
        Assert.Equal("InvalidOperationException", root["errors"]!["wfp_filters"]!.GetValue<string>());
        Assert.NotNull(root["logs"]);
        Assert.NotNull(root["snapshot"]);
    }

    [Fact]
    public async Task FirewallResultIsEmbeddedOrErrorCarried()
    {
        using var directory = new TempDirectory();
        var embedded = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            firewall: _ => Task.FromResult(new FirewallStateResult("{\"service\":\"Running\"}", null)))));
        Assert.Equal("Running", embedded["firewall"]!["service"]!.GetValue<string>());
        Assert.Null(embedded["firewall_error"]);
        var failed = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            firewall: _ => Task.FromResult(new FirewallStateResult(null, "x")))));
        Assert.Null(failed["firewall"]);
        Assert.Equal("x", failed["firewall_error"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StateFileIsSummarizedNotCopied(bool withBom)
    {
        using var directory = new TempDirectory();
        const string json = "{\"mode\":\"apps\",\"applied\":true,\"disabledRules\":[\"a1\",\"b2\",\"c3\"],"
            + "\"profiles\":[{\"Name\":\"Domain\"}],\"auth\":{\"ip\":\"x\",\"port\":1}}";
        File.WriteAllText(Path.Combine(directory.Path, "killswitch-state.json"), json, new UTF8Encoding(withBom));
        var summary = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)))
            ["killswitch"]!["state"]!["summary"]!.AsObject();
        Assert.Equal("apps", summary["mode"]!.GetValue<string>());
        Assert.True(summary["applied"]!.GetValue<bool>());
        Assert.Equal(3, summary["disabledRules_count"]!.GetValue<int>());
        Assert.Equal(1, summary["profiles_count"]!.GetValue<int>());
        Assert.Equal(new[] { "ip", "port" },
            summary["auth_keys"]!.AsArray().Select(node => node!.GetValue<string>()));
        Assert.False(summary.ContainsKey("disabledRules"));
    }

    [Fact]
    public async Task BrokenStateFileIsReported()
    {
        using var directory = new TempDirectory();
        File.WriteAllText(Path.Combine(directory.Path, "killswitch-state.json"), "不是 json");
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)));
        Assert.Null(root["killswitch"]!["state"]!["summary"]);
        Assert.Equal("不是有效的 JSON", root["errors"]!["killswitch_state"]!.GetValue<string>());
    }

    [Fact]
    public async Task MarkersReflectFiles()
    {
        using var directory = new TempDirectory();
        File.WriteAllText(Path.Combine(directory.Path, "wfp-off"), "");
        var killswitch = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)))["killswitch"]!;
        Assert.True(killswitch["wfp_off"]!.GetValue<bool>());
        Assert.False(killswitch["route_off"]!.GetValue<bool>());
    }

    [Fact]
    public async Task LogsAreTrimmedToFitBudget()
    {
        using var directory = new TempDirectory();
        var line = new string('中', 200);
        foreach (var name in DiagnosticsCollector.LogNames)
            File.WriteAllText(Path.Combine(directory.Path, name), string.Join("\n", Enumerable.Repeat(line, 2000)));
        var text = await DiagnosticsCollector.CollectAsync(Sources(directory));
        Assert.True(DiagnosticsCollector.EncodedBytes(text) <= DiagnosticsCollector.MaxEncodedBytes);
        var root = Parse(text);
        foreach (var name in DiagnosticsCollector.LogNames)
            Assert.True(root["logs"]![name]!["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task OversizeAuditIsOmittedAndNamed()
    {
        using var directory = new TempDirectory();
        var huge = "{\"items\":[" + string.Join(",", Enumerable.Repeat("{\"name\":\"abcd\"}", 150000)) + "]}";
        var text = await DiagnosticsCollector.CollectAsync(Sources(directory, audit: () => huge));
        Assert.True(DiagnosticsCollector.EncodedBytes(text) <= DiagnosticsCollector.MaxEncodedBytes);
        var root = Parse(text);
        Assert.Null(root["firewall_audit"]);
        Assert.Contains("firewall_audit",
            root["omitted"]!.AsArray().Select(node => node!.GetValue<string>()));
    }

    [Fact]
    public async Task AuditAndSelfCheckAreRedactedBeforeEmbedding()
    {
        using var directory = new TempDirectory();
        var text = await DiagnosticsCollector.CollectAsync(Sources(directory,
            audit: () => "{\"ip\":\"8.8.8.8\",\"path\":\"C:\\\\Users\\\\alice\\\\app.exe\"}",
            selfCheck: () => "{\"path\":\"C:\\\\Users\\\\alice\\\\app.exe\"}"));
        Assert.Contains("[公网地址]", text);
        Assert.Contains("[用户]", text);
        Assert.DoesNotContain("8.8.8.8", text);
        Assert.DoesNotContain("alice", text);
    }

    [Fact]
    public async Task InvalidAuditJsonIsDroppedWithError()
    {
        using var directory = new TempDirectory();
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory, audit: () => "不是 JSON")));
        Assert.Null(root["firewall_audit"]);
        Assert.Equal("不是有效的 JSON", root["errors"]!["firewall_audit"]!.GetValue<string>());
    }

    [Fact]
    public async Task AdapterAddressesAreRedacted()
    {
        using var directory = new TempDirectory();
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            adapters: () => new[]
            {
                new AdapterInfo("eth0", "网卡", [new AdapterAddress("8.8.4.4", 24), new AdapterAddress("192.168.1.5", 24)])
            })));
        Assert.Equal(new[] { "[公网地址]/24", "192.168.1.5/24" },
            root["adapters"]![0]!["ipv4"]!.AsArray().Select(node => node!.GetValue<string>()));
    }

    [Fact]
    public async Task CancellationPropagates()
    {
        using var directory = new TempDirectory();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DiagnosticsCollector.CollectAsync(
            Sources(directory, firewall: _ => throw new OperationCanceledException())));
    }
}
