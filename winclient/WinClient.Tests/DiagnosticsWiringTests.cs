using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Client;
using WinClient.Core.Diagnostics;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.Tests;

/// <summary>诊断后台接线单的用例：只走门面替身、命令替身与测试自建临时目录，不碰真系统。</summary>
public sealed class DiagnosticsWiringTests
{
    [Fact]
    public async Task OldFacadeWithoutOverrideReturnsNull()
    {
        IClientFacade facade = new OldFacade();
        Assert.Null(await facade.ReadDiagnosticsAsync());
    }

    [Fact]
    public async Task ReadDiagnosticsReturnsFacadeJson()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade { DiagnosticsText = "{\"schema\":1}" };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("read_diagnostics", cancellationToken: stop.Token);
            Assert.True(response.Ok);
            Assert.Null(response.Error);
            Assert.Equal("{\"schema\":1}", response.Diagnostics);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task ReadDiagnosticsIsTrustedOnly()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade { DiagnosticsText = "{\"schema\":1}" };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token, callerTrusted: false);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("read_diagnostics", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal(ControlServer.UntrustedCallerError, response.Error);
            Assert.Null(response.Diagnostics);
            Assert.Equal(0, facade.DiagnosticsCalls);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task ReadDiagnosticsUnsupportedWhenFacadeReturnsNull()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade { DiagnosticsText = null };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("read_diagnostics", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal("不支持的指令", response.Error);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task ReadDiagnosticsOversizeIsRejected()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var facade = new FakeFacade { DiagnosticsText = new string('a', 2 * 1024 * 1024) };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("read_diagnostics", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal("诊断内容过大，请联系管理员。", response.Error);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task ReadDiagnosticsFailureReturnsFixedError()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var facade = new FakeFacade { DiagnosticsFailure = new IOException("boom") };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (peer, host) = IpcTests.DuplexStream.Pair();
        var serving = server.ServeAsync(host, stop.Token);
        using (var client = new ControlClient(peer))
        {
            var response = await client.SendAsync("read_diagnostics", cancellationToken: stop.Token);
            Assert.False(response.Ok);
            Assert.Equal("诊断没有取到，请稍后再试。", response.Error);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public async Task ReadDiagnosticsDoesNotWaitForRunningCommand()
    {
        using var temp = new TempDirectory();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var facade = new FakeFacade { ConnectGate = gate, DiagnosticsText = "{\"schema\":1}" };
        var server = new ControlServer(facade, new DesiredStateStore(temp.Path));
        var (first, firstHost) = IpcTests.DuplexStream.Pair();
        var (second, secondHost) = IpcTests.DuplexStream.Pair();
        var serving = Task.WhenAll(server.ServeAsync(firstHost, stop.Token), server.ServeAsync(secondHost, stop.Token));
        using (var a = new ControlClient(first))
        using (var b = new ControlClient(second))
        {
            var connecting = a.SendAsync("connect", cancellationToken: stop.Token);
            await facade.ConnectEntered.Task.WaitAsync(stop.Token);
            // connect 还卡在门面里时，另一条连接的 read_diagnostics 仍须在 5 秒内拿到应答。
            var diagnostics = await b.SendAsync("read_diagnostics", cancellationToken: stop.Token)
                .WaitAsync(TimeSpan.FromSeconds(5), stop.Token);
            Assert.True(diagnostics.Ok);
            Assert.Equal("{\"schema\":1}", diagnostics.Diagnostics);
            Assert.False(connecting.IsCompleted);
            gate.SetResult();
            Assert.True((await connecting.WaitAsync(stop.Token)).Ok);
        }
        await serving.WaitAsync(stop.Token);
    }

    [Fact]
    public void KernelLogOffKeepsConfigurationUnchanged()
    {
        var configuration = KernelConfiguration();
        var current = TunnelTransport.RenderConfiguration(configuration).GetRawText();
        var explicitOff = TunnelTransport.RenderConfiguration(configuration, false).GetRawText();
        Assert.Equal(current, explicitOff);
        using var json = JsonDocument.Parse(explicitOff);
        Assert.True(json.RootElement.GetProperty("log").GetProperty("disabled").GetBoolean());
    }

    [Fact]
    public void KernelLogOnEnablesWarnLevelOnly()
    {
        var configuration = KernelConfiguration();
        var on = JsonNode.Parse(TunnelTransport.RenderConfiguration(configuration, true).GetRawText())!.AsObject();
        var off = JsonNode.Parse(TunnelTransport.RenderConfiguration(configuration, false).GetRawText())!.AsObject();
        Assert.False(on["log"]!["disabled"]!.GetValue<bool>());
        Assert.Equal("warn", on["log"]!["level"]!.GetValue<string>());
        Assert.True(on["log"]!["timestamp"]!.GetValue<bool>());
        on.Remove("log");
        off.Remove("log");
        Assert.Equal(off.ToJsonString(), on.ToJsonString());
    }

    [Fact]
    public void MaskDomainsHidesHostNamesAndKeepsMarks()
    {
        Assert.Equal("dial tcp [域名]:443: i/o timeout", DiagnosticsRedactor.MaskDomains("dial tcp www.example.com:443: i/o timeout"));
        Assert.Equal("[公网地址] 与 192.168.1.52 与 10.0.19045", DiagnosticsRedactor.MaskDomains("[公网地址] 与 192.168.1.52 与 10.0.19045"));
        Assert.Equal("", DiagnosticsRedactor.MaskDomains(null));
    }

    [Fact]
    public async Task CollectorMasksDomainsOnlyInKernelLog()
    {
        using var directory = new TempDirectory();
        File.WriteAllText(Path.Combine(directory.Path, "sing-box.log"), "连接 www.example.com 失败\n");
        File.WriteAllText(Path.Combine(directory.Path, "service.log"), "连接 www.example.com 失败\n");
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)));
        var kernel = root["logs"]!["sing-box.log"]!["lines"]!.AsArray().Select(node => node!.GetValue<string>()).ToArray();
        var service = root["logs"]!["service.log"]!["lines"]!.AsArray().Select(node => node!.GetValue<string>()).ToArray();
        Assert.Contains("[域名]", kernel[0]);
        Assert.DoesNotContain("www.example.com", kernel[0]);
        Assert.Contains("www.example.com", service[0]);
    }

    [Fact]
    public async Task SourcesCarryVersionTestBuildAndInjectedProbes()
    {
        using var directory = new TempDirectory();
        new DesiredStateStore(directory.Path).Write(true);
        var wfp = new FakeWfp(["YuanC-WFP-1"]);
        var runner = new RecordingRunner(_ => Task.FromResult(new CommandResult(0, "{}")));
        var adapters = new FakeAdapters([new AdapterInfo("eth0", "网卡", [new AdapterAddress("192.168.1.5", 24)])]);
        var sources = ClientRuntime.DiagnosticsSourcesFor(directory.Path,
            () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false), true, wfp, runner, adapters,
            () => "审计", () => "自检");
        Assert.Equal(ControlSnapshot.CurrentVersion, sources.Version);
        Assert.True(sources.TestBuild);
        Assert.True(sources.Desired!());
        Assert.Equal(new[] { "YuanC-WFP-1" }, sources.WfpFilterNames!());
        Assert.Equal("eth0", sources.Adapters!()![0].Name);
        Assert.Equal("审计", sources.Audit!());
        Assert.Equal("自检", sources.SelfCheck!());
        Assert.Null((await sources.Firewall!(CancellationToken.None)).Error);
        Assert.Null((await sources.Network!(CancellationToken.None)).Error);
        Assert.Equal(2, runner.StartInfos.Count);
        Assert.All(runner.StartInfos, info => Assert.True(info.CreateNoWindow));
        var withoutWfp = ClientRuntime.DiagnosticsSourcesFor(directory.Path,
            () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false), false, null, runner, adapters,
            () => null, () => null);
        Assert.Null(withoutWfp.WfpFilterNames);
        Assert.False(withoutWfp.TestBuild);
    }

    [Fact]
    public async Task StateSummaryKeepsProfileDefaults()
    {
        using var directory = new TempDirectory();
        const string state = "{\"applied\":true,\"mode\":\"all\",\"profiles\":[" +
            "{\"Name\":\"Domain\",\"DefaultOutboundAction\":\"Allow\",\"Enabled\":\"True\",\"Extra\":\"x\"}," +
            "{\"Name\":\"Private\",\"DefaultOutboundAction\":\"Block\",\"Enabled\":\"True\"},\"oops\"],\"rules\":[\"a\",\"b\"]}";
        File.WriteAllText(Path.Combine(directory.Path, "killswitch-state.json"), state);
        var summary = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)))
            ["killswitch"]!["state"]!["summary"]!.AsObject();
        Assert.Equal(3, summary["profiles_count"]!.GetValue<int>());
        var profiles = summary["profiles"]!.AsArray();
        Assert.Equal(2, profiles.Count);
        var first = profiles[0]!.AsObject();
        Assert.Equal("Domain", first["Name"]!.GetValue<string>());
        Assert.Equal("Allow", first["DefaultOutboundAction"]!.GetValue<string>());
        Assert.Equal("True", first["Enabled"]!.GetValue<string>());
        Assert.False(first.ContainsKey("Extra"));
        Assert.Equal("Block", profiles[1]!["DefaultOutboundAction"]!.GetValue<string>());
        Assert.Equal(2, summary["rules_count"]!.GetValue<int>());
        Assert.False(summary.ContainsKey("rules"));
    }

    [Fact]
    public void NetworkProbeScriptIsReadOnly()
    {
        var script = NetworkStateProbe.Script;
        Assert.Contains("Get-NetRoute", script);
        Assert.Contains("Get-NetIPInterface", script);
        Assert.Contains("Get-DnsClientServerAddress", script);
        foreach (var word in new[] { "Set-", "New-", "Remove-", "Enable-", "Disable-", "Stop-", "Restart-", "Add-", "Clear-" })
            Assert.DoesNotContain(word, script);
    }

    [Fact]
    public async Task NetworkProbeReturnsLastJsonLineOrError()
    {
        var ok = new RecordingRunner(_ => Task.FromResult(new CommandResult(0, "杂项\n{\"loopback_index\":1}\n")));
        var result = await NetworkStateProbe.RunAsync(ok);
        Assert.Equal("{\"loopback_index\":1}", result.Json);
        Assert.Null(result.Error);
        Assert.True(ok.StartInfos[0].CreateNoWindow);

        var failed = new RecordingRunner(_ => Task.FromResult(new CommandResult(1, "{\"loopback_index\":1}")));
        var failedResult = await NetworkStateProbe.RunAsync(failed);
        Assert.Null(failedResult.Json);
        Assert.Equal(NetworkStateProbe.Failed, failedResult.Error);

        var slow = new RecordingRunner(async (token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new CommandResult(0, "{}");
        });
        var timedOut = await NetworkStateProbe.RunAsync(slow, TimeSpan.FromMilliseconds(50));
        Assert.Null(timedOut.Json);
        Assert.Equal(NetworkStateProbe.TimedOut, timedOut.Error);

        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        var cancelled = new RecordingRunner(token =>
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult(new CommandResult(0, "{}"));
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            NetworkStateProbe.RunAsync(cancelled, TimeSpan.FromSeconds(5), cancel.Token));
    }

    [Fact]
    public async Task CollectorEmbedsNetworkAndKeepsRoutePrefixes()
    {
        using var directory = new TempDirectory();
        const string json = "{\"routes_active\":[{\"prefix\":\"128.0.0.0/1\",\"next_hop\":\"8.8.8.8\",\"alias\":\"以太网\"}]," +
            "\"dns\":[{\"servers\":[\"114.114.114.114\",\"192.168.1.1\"]}]}";
        var root = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            _ => Task.FromResult(new NetworkStateResult(json, null)))));
        var route = root["network"]!["routes_active"]![0]!;
        Assert.Equal("128.0.0.0/1", route["prefix"]!.GetValue<string>());
        Assert.Equal("[公网地址]", route["next_hop"]!.GetValue<string>());
        Assert.Equal(new[] { "[公网地址]", "192.168.1.1" },
            root["network"]!["dns"]![0]!["servers"]!.AsArray().Select(node => node!.GetValue<string>()));
        Assert.Null(root["network_error"]);

        var failed = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            _ => Task.FromResult(new NetworkStateResult(null, NetworkStateProbe.Failed)))));
        Assert.Null(failed["network"]);
        Assert.Equal(NetworkStateProbe.Failed, failed["network_error"]!.GetValue<string>());

        var thrown = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory,
            _ => throw new InvalidOperationException("boom"))));
        Assert.Null(thrown["network"]);
        Assert.Null(thrown["network_error"]);
        Assert.Equal("InvalidOperationException", thrown["errors"]!["network"]!.GetValue<string>());
        Assert.NotNull(thrown["logs"]);

        var withoutNetwork = Parse(await DiagnosticsCollector.CollectAsync(Sources(directory)));
        Assert.False(withoutNetwork.ContainsKey("network"));
        Assert.False(withoutNetwork.ContainsKey("network_error"));
    }

    private static JsonElement KernelConfiguration() => JsonDocument.Parse(
        "{\"log\":{\"disabled\":true},\"inbounds\":[{\"type\":\"tun\"}]}").RootElement;

    private static JsonObject Parse(string text) => JsonNode.Parse(text)!.AsObject();

    private static DiagnosticsSources Sources(TempDirectory directory,
        Func<CancellationToken, Task<NetworkStateResult>>? network = null) => new()
        {
            RunDirectory = directory.Path,
            Snapshot = () => new ClientSnapshot(ConnectionState.Disconnected, "未连接", "", false),
            Network = network,
            Now = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z")
        };

    /// <summary>只实现接线前的成员；read_diagnostics 走接口默认实现，返回空。</summary>
    private sealed class OldFacade : IClientFacade
    {
        public ClientSnapshot Snapshot { get; } = new(ConnectionState.Disconnected, "未连接", "", false);
        public event Action<ClientSnapshot>? Changed { add { } remove { } }
        public Task ConnectAsync() => Task.CompletedTask;
        public Task DisconnectAsync() => Task.CompletedTask;
        public Task SetRoutingAsync(string mode, IReadOnlyList<string> apps) => Task.CompletedTask;
        public Task SetEnvironmentEnabledAsync(bool enabled) => Task.CompletedTask;
        public Task RestoreEnvironmentAsync() => Task.CompletedTask;
        public Task RedeemAsync(string code) => Task.CompletedTask;
        public Task ImportPairingAsync(string json) => Task.CompletedTask;
        public Task ClearPairingAsync() => Task.CompletedTask;
        public string? ReadAudit() => null;
        public string? ReadSelfCheck() => null;
    }

    private sealed class FakeFacade : IClientFacade
    {
        public ClientSnapshot Snapshot { get; } = new(ConnectionState.Disconnected, "未连接", "", false);
        public event Action<ClientSnapshot>? Changed { add { } remove { } }
        public string? DiagnosticsText { get; init; }
        public Exception? DiagnosticsFailure { get; init; }
        public TaskCompletionSource? ConnectGate { get; init; }
        public TaskCompletionSource ConnectEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int DiagnosticsCalls { get; private set; }
        public async Task ConnectAsync()
        {
            ConnectEntered.TrySetResult();
            if (ConnectGate is { } gate) await gate.Task;
        }
        public Task DisconnectAsync() => Task.CompletedTask;
        public Task SetRoutingAsync(string mode, IReadOnlyList<string> apps) => Task.CompletedTask;
        public Task SetEnvironmentEnabledAsync(bool enabled) => Task.CompletedTask;
        public Task RestoreEnvironmentAsync() => Task.CompletedTask;
        public Task RedeemAsync(string code) => Task.CompletedTask;
        public Task ImportPairingAsync(string json) => Task.CompletedTask;
        public Task ClearPairingAsync() => Task.CompletedTask;
        public string? ReadAudit() => null;
        public string? ReadSelfCheck() => null;
        public Task<string?> ReadDiagnosticsAsync(CancellationToken token = default)
        {
            DiagnosticsCalls++;
            if (DiagnosticsFailure is not null) throw DiagnosticsFailure;
            return Task.FromResult(DiagnosticsText);
        }
    }

    private sealed class FakeWfp(IReadOnlyList<string> names) : IWfpEngine
    {
        public void Install(IReadOnlyList<WfpFilterSpec> filters) { }
        public void Remove() { }
        public IReadOnlyList<string> ListFilterNames() => names;
    }

    private sealed class FakeAdapters(IReadOnlyList<AdapterInfo> adapters) : IAdapterProbe
    {
        public IReadOnlyList<AdapterInfo>? Snapshot() => adapters;
    }

    private sealed class RecordingRunner(Func<CancellationToken, Task<CommandResult>> behavior) : ICommandRunner
    {
        public List<ProcessStartInfo> StartInfos { get; } = [];
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            StartInfos.Add(startInfo);
            return behavior(cancellationToken);
        }
    }
}
