using System.Net;
using System.Text.Json;
using WinClient.Core.Auth;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using WinClient.Core.State;
using WinClient.Core.Storage;
using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class ControllerTests
{
    [Fact]
    public async Task RoutePatrolFailureKeepsTunnelAndShowsOriginalWarning()
    {
        var order = new List<string>(); var timers = new Timers();
        var firewall = new Firewall(order);
        firewall.PatrolResults.Enqueue(new RouteGuardUnavailableException(KillSwitchApplier.RoutePatrolFailed));
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.Combine(Path.GetTempPath(), "fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(KillSwitchApplier.RoutePatrolFailed, controller.Snapshot.Message);
        Assert.Equal(KillSwitchApplier.RoutePatrolFailed, controller.Snapshot.GuardStatus);
        Assert.DoesNotContain("stop", order);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task HeldProtectionKeepsTunnelWhenRoutesFail()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true,
            ApplyError = new RouteGuardUnavailableException(KillSwitchApplier.RouteConnectRefused) };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.Combine(Path.GetTempPath(), "fake.exe"), TestData.Device);
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.Equal(ClientController.RouteKeepTunnelWarning, controller.Snapshot.Message);
        Assert.Equal(ClientController.RouteKeepTunnelWarning, controller.Snapshot.GuardStatus);
    }

    private sealed class ScriptedBrowserProbe(params IReadOnlyList<string>?[] results) : IBrowserProcessProbe
    {
        private int index;
        public IReadOnlyList<string>? RunningBrowsers() => results[Math.Min(index++, results.Length - 1)];
    }

    [Fact]
    public async Task 浏览器运行时首次连接只提醒两分钟内再次点击才连接()
    {
        var order = new List<string>();
        var now = DateTimeOffset.Parse("2026-10-23T00:00:00Z");
        using var controller = EnvironmentController(order, new FakeEnvironment(order), new MemoryEnvironmentSettings(),
            browserProbe: new ScriptedBrowserProbe(["Chrome"]));
        controller.NowProvider = () => now;
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.Empty(order);
        Assert.Contains("Chrome 正在运行:连接", controller.Snapshot.Message);
        Assert.Contains(ClientController.BrowserWarningMarker, controller.Snapshot.Message);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(new[] { "apply", "start", "env-apply" }, order);
    }

    [Fact]
    public async Task 浏览器提醒超过两分钟需要重新确认()
    {
        var order = new List<string>();
        var now = DateTimeOffset.Parse("2026-10-23T00:00:00Z");
        using var controller = EnvironmentController(order, new FakeEnvironment(order), new MemoryEnvironmentSettings(),
            browserProbe: new ScriptedBrowserProbe(["Chrome"]));
        controller.NowProvider = () => now;
        await controller.ConnectAsync();
        now += TimeSpan.FromMinutes(3);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.Empty(order);
        Assert.Contains(ClientController.BrowserWarningMarker, controller.Snapshot.Message);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains("start", order);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task 自动连接包括保持保护分路都不提醒浏览器(bool keep)
    {
        var order = new List<string>();
        var timers = new Timers();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order) { HasPendingState = keep }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            timers.Delay, environment: new FakeEnvironment(order) { HasPendingState = keep },
            environmentSettings: new MemoryEnvironmentSettings(), browserProbe: new ScriptedBrowserProbe(["Edge"]));
        await controller.InitializeAsync(autoConnect: true, keepProtection: keep);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains("apply", order);
        Assert.Contains("start", order);
        Assert.DoesNotContain(ClientController.BrowserWarningMarker, controller.Snapshot.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task 总开关关闭或没有环境执行器时直接连接(bool missingEnvironment)
    {
        var order = new List<string>();
        using var controller = EnvironmentController(order, missingEnvironment ? null : new FakeEnvironment(order),
            new MemoryEnvironmentSettings { Enabled = missingEnvironment }, browserProbe: new ScriptedBrowserProbe(["Chrome"]));
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.DoesNotContain(ClientController.BrowserWarningMarker, controller.Snapshot.Message);
    }

    [Fact]
    public async Task 浏览器运行时首次断开保持连接和保护再次点击才恢复()
    {
        var order = new List<string>();
        using var controller = EnvironmentController(order, new FakeEnvironment(order), new MemoryEnvironmentSettings(),
            browserProbe: new ScriptedBrowserProbe([], [], ["Chrome", "Edge"]));
        controller.NowProvider = () => DateTimeOffset.Parse("2026-10-23T00:00:00Z");
        await controller.ConnectAsync();
        var before = order.ToArray();
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("Chrome 与 Edge 正在运行:断开", controller.Snapshot.Message);
        Assert.Contains(ClientController.BrowserWarningMarker, controller.Snapshot.Message);
        Assert.Equal(before, order);
        Assert.DoesNotContain("env-restore", order);
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(1, order.Count(item => item == "env-restore"));
    }

    [Fact]
    public async Task 自检记录套用瞬间的浏览器而非提醒时的清单()
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        var reports = new List<EnvironmentReport>();
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: new DetailedProbe(), environment: new InspectableEnvironment(false),
            environmentSettings: new MemoryEnvironmentSettings(), ipv6Probe: new ScriptedIpv6(false), reportSink: reports.Add,
            adapterProbe: new StaticAdapterProbe(TunAdapters), browserProbe: new ScriptedBrowserProbe([], ["Chrome"]))
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        var report = Assert.Single(reports);
        Assert.Equal(12, report.Items.Count);
        Assert.Equal("未通过", report.Items[9].Result);
        Assert.Contains("Chrome", report.Items[9].Detail);
        Assert.Equal("1 项未通过:浏览器在环境切换前已关闭", report.Summary);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
    }

    [Fact]
    public async Task ForceRestoreRejectsConnectedWithoutChangingEnvironmentOrFirewall()
    {
        var order = new List<string>(); var environment = new ForceRestoreEnvironment();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, environment: environment);
        await controller.ConnectAsync();
        var before = controller.Snapshot; var actions = order.ToArray();
        await controller.ForceRestoreEnvironmentAsync();
        Assert.Equal("请先断开连接,再强制恢复默认环境。", controller.Snapshot.Message);
        Assert.Equal(0, environment.Calls);
        Assert.Equal(before.State, controller.Snapshot.State);
        Assert.Equal(before.ProtectionActive, controller.Snapshot.ProtectionActive);
        Assert.Equal(before.EnvironmentStatus, controller.Snapshot.EnvironmentStatus);
        Assert.Equal(actions, order);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task ForceRestoreDisconnectedReportsResultWithoutFirewallActions(bool record, bool fail)
    {
        var order = new List<string>();
        var environment = new ForceRestoreEnvironment { HasPendingState = record, Fail = fail };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, environment: environment);
        await controller.ForceRestoreEnvironmentAsync();
        Assert.Equal(1, environment.Calls);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Empty(order);
        Assert.Equal(fail ? "恢复失败,请联系管理员" : "未应用", controller.Snapshot.EnvironmentStatus);
        if (fail) Assert.Equal("强制恢复未完成,请联系管理员。", controller.Snapshot.Message);
        else Assert.Contains(record ? "已按恢复记录" : "没有恢复记录", controller.Snapshot.Message);
        Assert.Equal(EnvironmentSettingsStore.Default.Target.Languages, environment.Target!.Languages);
    }

    private sealed class ForceRestoreEnvironment : IEnvironmentEnforcer
    {
        public bool HasPendingState { get; set; }
        public bool Fail { get; init; }
        public int Calls { get; private set; }
        public EnvironmentTarget? Target { get; private set; }
        public Task ApplyAsync(EnvironmentTarget target) => Task.CompletedTask;
        public Task RestoreAsync() => Task.CompletedTask;
        public Task ForceRestoreAsync(EnvironmentTarget target)
        {
            Calls++; Target = target;
            if (Fail) throw new InvalidOperationException("测试恢复失败");
            return Task.CompletedTask;
        }
    }

    private sealed class MemoryRouting : IRoutingSettingsStore
    {
        public RoutingPolicy Policy = RoutingTests.Apps;
        public int Writes;
        public RoutingPolicy Read() => Policy;
        public void Write(RoutingPolicy policy) { Writes++; Policy = policy; }
    }
    private static SessionResponse AppsSession(string host = "192.0.2.5") => TestData.SessionExpiringIn(
        TimeSpan.FromHours(6), node: TestData.Node(host: host));

    [Fact]
    public async Task ServerProvidedSingboxConfigIsIgnored()
    {
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
        var payload = JsonSerializer.SerializeToNode(TestData.SessionExpiringIn(TimeSpan.FromHours(6)), options)!;
        payload["singbox_config"] = System.Text.Json.Nodes.JsonNode.Parse(
            """{"outbounds":[{"type":"direct","tag":"direct"}]}""");
        var json = payload.ToJsonString();
        var session = JsonSerializer.Deserialize<SessionResponse>(json, options);
        Assert.NotNull(session);
        Assert.Null(typeof(SessionResponse).GetProperty("SingboxConfig"));
        Assert.False(JsonSerializer.SerializeToElement(session, options).TryGetProperty("singbox_config", out _));

        var order = new List<string>();
        var tunnel = new Tunnel(order);
        var credentials = new InMemoryCredentialStore(); credentials.Save("test-refresh");
        using var http = new HttpClient(new AuthTests.Handler(_ => new(HttpStatusCode.OK)
        { Content = new StringContent(json) })) { BaseAddress = new("https://unit.invalid") };
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), credentials),
            new Firewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device,
            routingSettings: new MemoryRouting { Policy = RoutingPolicy.Global }, serviceProcessPath: RoutingTests.Service,
            authEndpoint: new(IPAddress.Parse("192.0.2.5"), 8080, RoutingTests.Service));
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(RoutingRenderer.Render(WinClient.Core.Pairing.LocalConfigRenderer.Render(session.Node),
            RoutingPolicy.Global, RoutingTests.Service, new(IPAddress.Parse("192.0.2.5"), 8080, RoutingTests.Service)).GetRawText(), tunnel.Config.GetRawText());
        var direct = Assert.Single(tunnel.Config.GetProperty("route").GetProperty("rules").EnumerateArray(),
            rule => rule.TryGetProperty("outbound", out var outbound) && outbound.GetString() == "direct");
        Assert.Equal("192.0.2.5/32", Assert.Single(direct.GetProperty("ip_cidr").EnumerateArray()).GetString());
        Assert.Equal(8080, Assert.Single(direct.GetProperty("port").EnumerateArray()).GetInt32());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AppsAppliesOnlyUserProgramsAndRendersAuthOnlyForDistribution(bool distribution)
    {
        var order = new List<string>(); var firewall = new Firewall(order); var tunnel = new Tunnel(order);
        var credentials = new InMemoryCredentialStore(); credentials.Save("test-refresh");
        using var http = SessionHttp(() => AppsSession());
        ISessionSource source = distribution ? new AuthServerSessionSource(new AuthApiClient(http), credentials)
            : new PairingSessionSource(PairingTests.ValidPairing());
        using var controller = new ClientController(source, firewall, tunnel, Path.GetFullPath("fake.exe"), TestData.Device,
            routingSettings: new MemoryRouting(), serviceProcessPath: RoutingTests.Service,
            authEndpoint: new(IPAddress.Parse("192.0.2.5"), 8080, RoutingTests.Service));
        await controller.ConnectAsync();
        Assert.Equal(new[] { "apply-apps", "start" }, order);
        Assert.Equal(new[] { RoutingTests.Chrome }, firewall.AppliedApps);
        var rules = tunnel.Config.GetProperty("route").GetProperty("rules").EnumerateArray().ToArray();
        Assert.Contains(RoutingRenderer.PathPattern(RoutingTests.Service), rules[^3].GetProperty("process_path_regex").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal("{\"action\":\"reject\"}", rules[^1].GetRawText());
        // 名单外认得出的程序直连规则(无地址限制)始终存在;鉴权直连规则(带地址)只在分发版出现。
        Assert.Equal(distribution, rules.Any(r => r.TryGetProperty("outbound", out var outbound)
            && outbound.GetString() == "direct" && r.TryGetProperty("ip_cidr", out _)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AppsRejectsMismatchOrEmptyListBeforeStateMachine(bool mismatch)
    {
        var order = new List<string>(); var store = new MemoryRouting();
        if (!mismatch) store.Policy = RoutingPolicy.Create("apps", []);
        var firewall = new Firewall(order) { HasPendingState = mismatch, PendingMode = "global" };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()), firewall,
            new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, routingSettings: store);
        await controller.ConnectAsync();
        Assert.Empty(order); Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.Contains(mismatch ? "不一致" : "至少要选一个程序", controller.Snapshot.Message);
    }

    [Fact]
    public async Task SetRoutingAsyncRequiresDisconnectedAndNoRecoveryRecord()
    {
        var order = new List<string>(); var store = new MemoryRouting { Policy = RoutingPolicy.Global };
        var firewall = new Firewall(order) { HasPendingState = true };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()), firewall,
            new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, routingSettings: store, serviceProcessPath: RoutingTests.Service);
        await controller.SetRoutingAsync("apps", [RoutingTests.Chrome]);
        Assert.Contains("恢复记录尚在", controller.Snapshot.Message); Assert.Equal(0, store.Writes);
        firewall.HasPendingState = false;
        await controller.ConnectAsync();
        await controller.SetRoutingAsync("apps", [RoutingTests.Chrome]);
        Assert.Equal("请先断开连接,再更改代理范围。", controller.Snapshot.Message); Assert.Equal(0, store.Writes);
        await controller.DisconnectAsync();
        await controller.SetRoutingAsync("apps", [RoutingTests.Chrome]);
        Assert.Equal(1, store.Writes); Assert.Equal("apps", controller.Snapshot.RoutingMode);
        Assert.Equal(new[] { RoutingTests.Chrome }, controller.Snapshot.RoutingApps);
        await controller.SetRoutingAsync("bad", []);
        Assert.Equal(1, store.Writes); Assert.Equal("apps", controller.Snapshot.RoutingMode);
    }

    [Fact]
    public async Task AppsPatrolRebuildsWithoutDefaultBlockAndSelfCheckSkipsIpv6()
    {
        var order = new List<string>(); var timers = new Timers(); var firewall = new Firewall(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(AppsSession()));
        var ipv6 = new ScriptedIpv6(true); var reports = new List<EnvironmentReport>();
        using var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            timers.Delay, routingSettings: new MemoryRouting(), serviceProcessPath: RoutingTests.Service,
            exitProbe: new DetailedProbe(), ipv6Probe: ipv6, reportSink: reports.Add) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        firewall.PatrolResults.Enqueue(new PatrolReport([], [], [KillSwitchPlanner.AppPrefix + "1"]));
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.False(Assert.Single(firewall.EnforceDefaultCalls));
        Assert.Equal(KillSwitchPlanner.AppRuleNames(1), Assert.Single(firewall.PatrolCalls));
        Assert.Equal(2, order.Count(x => x == "apply-apps"));
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Equal(0, ipv6.Calls); Assert.Equal("跳过", Assert.Single(reports).Items[7].Result);
        Assert.Equal("已核验(后台服务出口)", controller.Snapshot.ExitStatus);
    }

    private const string ScopeDir = @"C:\Apps\Tool";
    private static readonly string ScopeSelected = ScopeDir + @"\app-1.0.0\tool.exe";
    private static readonly string ScopePattern = @"(?i)^C:\\Apps\\Tool\\.+\.exe$";

    private static Func<string, AppScope> ScopeOf(List<string> files) =>
        path => new(path, ScopePattern, files.Append(path).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(), true);

    private static ClientController ScopeController(List<string> order, Timers timers, Firewall firewall, FakeReaper? reaper,
        List<string> files, List<EnvironmentReport>? reports = null)
    {
        var source = new ScriptedSource(); source.Enqueue(Ok(AppsSession()));
        var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            timers.Delay, routingSettings: new MemoryRouting { Policy = RoutingPolicy.Create("apps", [ScopeSelected]) },
            serviceProcessPath: RoutingTests.Service, exitProbe: new DetailedProbe(), reaper: reaper, reportSink: reports is null ? null : reports.Add,
            scopeResolver: ScopeOf(files)) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        return controller;
    }

    [Fact]
    public async Task AppsModeRendersScopePatterns()
    {
        var order = new List<string>(); var timers = new Timers(); var reports = new List<EnvironmentReport>();
        var source = new ScriptedSource(); source.Enqueue(Ok(AppsSession()));
        var tunnel = new Tunnel(order);
        using var controller = new ClientController(source, new Firewall(order), tunnel, Path.GetFullPath("fake.exe"), TestData.Device,
            timers.Delay, routingSettings: new MemoryRouting { Policy = RoutingPolicy.Create("apps", [ScopeSelected]) },
            serviceProcessPath: RoutingTests.Service, exitProbe: new DetailedProbe(), reportSink: reports.Add,
            scopeResolver: ScopeOf([ScopeDir + @"\Update.exe"])) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        var rules = tunnel.Config.GetProperty("route").GetProperty("rules").EnumerateArray().ToArray();
        var proxy = Assert.Single(rules, r => r.TryGetProperty("outbound", out var o) && o.GetString() == "proxy");
        var patterns = proxy.GetProperty("process_path_regex").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Contains(ScopePattern, patterns);
        Assert.DoesNotContain(RoutingRenderer.PathPattern(ScopeSelected), patterns);
        Assert.Equal("{\"action\":\"reject\"}", rules[^1].GetRawText());
        // 自检按连带范围匹配式比对,不会因路径匹配式缺失而未通过。
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Equal("通过", Assert.Single(reports).Items[6].Result);
    }

    [Fact]
    public async Task AppsModePassesScopeExecutablesToFilters()
    {
        var order = new List<string>(); var firewall = new Firewall(order);
        var files = new List<string> { ScopeDir + @"\Update.exe", ScopeDir + @"\app-1.0.0\TOOL.exe" };
        using var controller = ScopeController(order, new Timers(), firewall, null, files);
        await controller.ConnectAsync();
        // 防火墙规则仍按所选程序;过滤层按全部程序文件(不分大小写去重)。
        Assert.Equal(new[] { ScopeSelected }, firewall.AppliedApps);
        var filters = Assert.Single(firewall.AppliedFilters);
        Assert.Equal(2, filters.Length);
        Assert.Contains(ScopeDir + @"\Update.exe", filters);
        Assert.Contains(filters, f => string.Equals(f, ScopeSelected, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AppsModeReapsScopeExecutables()
    {
        var order = new List<string>(); var reaper = new FakeReaper(order);
        var files = new List<string> { ScopeDir + @"\Update.exe" };
        using var controller = ScopeController(order, new Timers(), new Firewall(order), reaper, files);
        await controller.ConnectAsync();
        var policy = Assert.Single(reaper.Policies);
        Assert.True(policy.AppsMode);
        Assert.Equal(new[] { ScopeDir + @"\Update.exe", ScopeSelected }.Order(StringComparer.OrdinalIgnoreCase), policy.Apps);
    }

    [Fact]
    public async Task PatrolAddsProtectionForNewExecutables()
    {
        var order = new List<string>(); var timers = new Timers(); var firewall = new Firewall(order);
        var files = new List<string> { ScopeDir + @"\Update.exe" };
        using var controller = ScopeController(order, timers, firewall, null, files);
        await controller.ConnectAsync();
        Assert.Single(firewall.AppliedFilters);
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Single(firewall.AppliedFilters); // 没有新增:不重复套用。
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
        files.AddRange([ScopeDir + @"\app-1.0.1\tool.exe", ScopeDir + @"\helper.exe"]);
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Equal(2, firewall.AppliedFilters.Count);
        Assert.Equal(4, firewall.AppliedFilters[^1].Length);
        Assert.Equal(new[] { ScopeSelected }, firewall.AppliedApps);
        Assert.Equal("已为新出现的 2 个程序文件补上保护", controller.Snapshot.GuardStatus);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("remove", order);
        // 文件消失不撤保护;下一轮没有新增,恢复为正常。
        files.Clear();
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Equal(2, firewall.AppliedFilters.Count);
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
    }

    [Fact]
    public async Task AppsNodeChangeDoesNotUpdateAllowRulesOrProbeDuringReconnect()
    {
        var order = new List<string>(); var timers = new Timers(); var source = new ScriptedSource();
        source.Enqueue(Ok(AppsSession())); var probe = new ScriptedProbe(IPAddress.Parse("192.0.2.5"));
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: probe, routingSettings: new MemoryRouting(), serviceProcessPath: RoutingTests.Service)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        source.Enqueue(Ok(AppsSession("192.0.2.6")));
        await controller.RefreshSessionAsync();
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.DoesNotContain(order, x => x.StartsWith("update", StringComparison.Ordinal));
        var calls = probe.Calls;
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Equal(calls, probe.Calls);
    }

    [Fact]
    public async Task PairingEnvironmentUsesNodeTimeZoneAndCountryForSelfCheck()
    {
        var document = PairingTests.ValidDocument();
        document["node"]!["time_zone"] = "W. Australia Standard Time";
        document["node"]!["country"] = "NZ";
        var pair = WinClient.Core.Pairing.PairingFile.Parse(document.ToJsonString());
        var order = new List<string>();
        var timers = new Timers();
        var environment = new FakeEnvironment(order);
        var reports = new List<EnvironmentReport>();
        using var controller = new ClientController(new PairingSessionSource(pair), new Firewall(order), new Tunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay, environment: environment,
            environmentSettings: new MemoryEnvironmentSettings(), exitProbe: new NodeCountryProbe(pair.Node.Host),
            reportSink: reports.Add) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        Assert.Equal("W. Australia Standard Time", Assert.Single(environment.Targets).TimeZoneId);
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Equal("通过", Assert.Single(reports).Items.Single(item => item.Id == "exit_country").Result);
        Assert.Equal("通过", Assert.Single(reports).Items.Single(item => item.Id == "time_zone").Result);
    }

    [Theory]
    [InlineData("W. Australia Standard Time", "", "")]
    [InlineData("", "", "")]
    [InlineData("W. Australia Standard Time", "恢复", "")]
    [InlineData("W. Australia Standard Time", "套用", "")]
    [InlineData("AUS Eastern Standard Time", "", "NZ")]
    public async Task RenewalOnlyReappliesChangedTimeZoneWithoutRestartingTunnel(string zone, string failure, string country)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource();
        // 空字段续期覆盖从节点时区回到本机配置的分路。
        var originalZone = zone == "" ? "W. Australia Standard Time" : "AUS Eastern Standard Time";
        var first = TestData.SessionExpiringIn(TimeSpan.FromHours(6), node: TestData.Node(timeZone: originalZone));
        source.Enqueue(Ok(first));
        var environment = new FakeEnvironment(order);
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay, environment: environment,
            environmentSettings: new MemoryEnvironmentSettings()) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        order.Clear();
        if (failure == "恢复") environment.RestoreError = new IOException("模拟恢复失败");
        if (failure == "套用") environment.ApplyError = new IOException("模拟套用失败");
        var next = TestData.SessionExpiringIn(TimeSpan.FromHours(7), node: TestData.Node(timeZone: zone, country: country));
        Assert.True(ClientController.SameSession(first, next));
        source.Enqueue(Ok(next));
        timers.Fire("续期", d => Near(d, TimeSpan.FromHours(4.8)));
        await Until(() => timers.For("续期").Length == 2);
        await controller.ConnectAsync(); // 等续期回调释放串行锁。
        Assert.Equal(zone == originalZone ? Array.Empty<string>() : failure == "恢复"
            ? new[] { "env-restore" } : new[] { "env-restore", "env-apply" }, order);
        Assert.DoesNotContain("stop", order);
        Assert.DoesNotContain("start", order);
        if (failure != "恢复")
            Assert.Equal(zone == "" ? "AUS Eastern Standard Time" : zone, environment.Targets.Last().TimeZoneId);
        Assert.Equal(failure switch
        {
            "恢复" => "恢复失败,请联系管理员",
            "套用" => "设置失败,请联系管理员;连接与断网保护不受影响",
            _ => "已切换到澳洲时区与浏览器策略"
        }, controller.Snapshot.EnvironmentStatus);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
        Assert.True(controller.Snapshot.ProtectionActive);
    }

    private sealed class NodeCountryProbe(string host) : IExitProbe
    {
        public Task<IPAddress?> ProbeAsync(CancellationToken token) => Task.FromResult<IPAddress?>(IPAddress.Parse(host));
        public Task<ExitProbeResult?> ProbeDetailedAsync(CancellationToken token)
            => Task.FromResult<ExitProbeResult?>(new(IPAddress.Parse(host), "NZ"));
    }

    [Theory]
    [InlineData("192.0.2.5", false)]
    [InlineData("198.51.100.9", false)]
    [InlineData("192.0.2.5", true)]
    [InlineData(null, false)]
    public async Task ExitTerminalRunsEightChecksWithoutChangingConnection(string? address, bool ipv6Reachable)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        var reports = new List<EnvironmentReport>();
        var ipv6 = new ScriptedIpv6(ipv6Reachable);
        var probe = new ScriptedProbe(Enumerable.Repeat(address is null ? null : IPAddress.Parse(address), 5).ToArray());
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: probe, ipv6Probe: ipv6, reportSink: reports.Add, adapterProbe: new StaticAdapterProbe(TunAdapters))
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        if (address is null)
        {
            Assert.Empty(reports);
            for (var i = 1; i < 5; i++) await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(5));
        }
        var report = Assert.Single(reports);
        Assert.Equal(12, report.Items.Count);
        Assert.Equal(report.Summary, controller.Snapshot.SelfCheckStatus);
        Assert.DoesNotContain(controller.Snapshot.SelfCheckStatus, new[] { "未检测", "检测中" });
        Assert.Equal(1, ipv6.Calls);
        if (address is null) Assert.All(report.Items.Take(2), item => Assert.Equal("无法核验", item.Result));
        if (ipv6Reachable) Assert.Contains("IPv6 已封堵", controller.Snapshot.SelfCheckStatus);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("stop", order); Assert.DoesNotContain("remove", order);
        if (address is "192.0.2.5") Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
        if (address is null) Assert.Equal(ClientController.AuthUnverifiableHint, controller.Snapshot.Message);
        if (address is not null)
        {
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromMinutes(5));
            Assert.Equal(2, reports.Count);
        }
        await controller.DisconnectAsync();
        Assert.Equal("未检测", controller.Snapshot.SelfCheckStatus);
    }

    [Fact]
    public async Task SelfCheckIncludesProxyFindingsFromProbe()
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        var reports = new List<EnvironmentReport>();
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: new DetailedProbe(), ipv6Probe: new ScriptedIpv6(false),
            reportSink: reports.Add, adapterProbe: new StaticAdapterProbe(TunAdapters),
            proxyProbe: new StaticProxyProbe(["系统代理"])) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        var report = Assert.Single(reports);
        var item = report.Items[report.Items.Count - 1];
        Assert.Equal("system_proxy", item.Id);
        Assert.Equal("未通过", item.Result);
    }

    private sealed class StaticProxyProbe(IReadOnlyList<string>? findings) : IProxySettingsProbe
    {
        public IReadOnlyList<string>? Snapshot() => findings;
    }

    private static IReadOnlyList<AdapterInfo> TunAdapters =>
        [new(KillSwitchPlanner.TunAlias, "Wintun Userspace Tunnel", [new("172.19.0.1", 30)])];

    private sealed class StaticAdapterProbe(IReadOnlyList<AdapterInfo>? adapters) : IAdapterProbe
    {
        public IReadOnlyList<AdapterInfo>? Snapshot() => adapters;
    }

    private sealed class ThrowingAdapterProbe : IAdapterProbe
    {
        public IReadOnlyList<AdapterInfo>? Snapshot() => throw new InvalidOperationException("模拟网卡清单读取失败");
    }

    [Fact]
    public async Task 网卡探测失败仍出报告且保持连接和保护()
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        var reports = new List<EnvironmentReport>();
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: new DetailedProbe(),
            environment: new InspectableEnvironment(false), ipv6Probe: new ScriptedIpv6(false),
            reportSink: reports.Add, adapterProbe: new ThrowingAdapterProbe())
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        var report = Assert.Single(reports);
        Assert.Equal(12, report.Items.Count);
        Assert.Equal("无法核验", report.Items[8].Result);
        Assert.Equal("未取得本机网卡清单", report.Items[8].Detail);
        Assert.Equal("8 项通过,4 项未能检查", report.Summary);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.Contains(TimeSpan.FromMinutes(5), timers.For("出口核验"));
    }
    private sealed class ScriptedIpv6(bool reachable) : IIpv6Probe
    {
        public int Calls;
        public Task<bool> CanReachAsync(CancellationToken token) { Calls++; return Task.FromResult(reachable); }
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task SelfCheckInspectsOnlyWhenEnabledAndFailuresCannotAffectConnection(bool enabled, bool fail)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource();
        source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(6))));
        var environment = new InspectableEnvironment(fail);
        var reports = new List<EnvironmentReport>();
        var snapshots = new List<ClientSnapshot>();
        using var controller = new ClientController(source, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: new DetailedProbe(), environment: environment,
            environmentSettings: new MemoryEnvironmentSettings { Enabled = enabled },
            ipv6Probe: fail ? new ThrowingIpv6() : new ScriptedIpv6(false), reportSink: report =>
            {
                reports.Add(report);
                if (fail) throw new IOException("模拟报告写入失败");
            }, adapterProbe: new StaticAdapterProbe(TunAdapters)) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += snapshot => { snapshots.Add(snapshot); Interlocked.Increment(ref timers.Published); };
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Equal(enabled ? 1 : 0, environment.Inspections);
        var report = Assert.Single(reports);
        Assert.Contains(snapshots, snapshot => snapshot.SelfCheckStatus == "检测中");
        Assert.Equal(report.Summary, controller.Snapshot.SelfCheckStatus);
        Assert.Equal(fail ? "5 项通过,7 项未能检查" : enabled ? "10 项通过,2 项未能检查" : "6 项通过,6 项未能检查", report.Summary);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.Contains(TimeSpan.FromMinutes(5), timers.For("出口核验"));
    }

    private sealed class DetailedProbe : IExitProbe
    {
        public Task<IPAddress?> ProbeAsync(CancellationToken token) => throw new InvalidOperationException("控制器应使用详细探测");
        public Task<ExitProbeResult?> ProbeDetailedAsync(CancellationToken token)
            => Task.FromResult<ExitProbeResult?>(new(IPAddress.Parse(TestData.Node().Host), "AU"));
    }

    private sealed class ThrowingIpv6 : IIpv6Probe
    {
        public Task<bool> CanReachAsync(CancellationToken token) => throw new System.Net.Sockets.SocketException();
    }

    private sealed class InspectableEnvironment(bool fail) : IEnvironmentEnforcer
    {
        public int Inspections;
        public bool HasPendingState => false;
        public Task ApplyAsync(EnvironmentTarget target) => Task.CompletedTask;
        public Task RestoreAsync() => Task.CompletedTask;
        public Task<EnvironmentInspection?> InspectAsync()
        {
            Inspections++;
            if (fail) throw new IOException("模拟巡查失败");
            return Task.FromResult<EnvironmentInspection?>(EnvironmentSelfCheckTests.GoodInspection);
        }
    }

    [Fact]
    public async Task EnvironmentAppliesAfterTunnelAndRestoresAfterNetwork()
    {
        var order = new List<string>();
        var env = new FakeEnvironment(order);
        using var controller = EnvironmentController(order, env, new MemoryEnvironmentSettings());
        await controller.ConnectAsync();
        Assert.Equal(new[] { "apply", "start", "env-apply" }, order);
        Assert.Contains("已切换", controller.Snapshot.EnvironmentStatus);
        Assert.True(controller.Snapshot.EnvironmentEnabled);
        await controller.DisconnectAsync();
        Assert.Equal(new[] { "stop", "remove", "env-restore" }, order.TakeLast(3));
        Assert.Equal("未应用", controller.Snapshot.EnvironmentStatus);
        await controller.ConnectAsync();
        Assert.Equal(2, order.Count(x => x == "env-apply"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EnvironmentApplyFailureCannotStopTunnelOrChangeConnectionMessage(bool verify)
    {
        var order = new List<string>();
        var env = new FakeEnvironment(order) { ApplyError = verify ? new EnvironmentVerifyException("模拟锁定") : new IOException("模拟失败") };
        using var controller = EnvironmentController(order, env, new MemoryEnvironmentSettings());
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start", "env-apply" }, order);
        Assert.Contains("设置失败", controller.Snapshot.EnvironmentStatus);
        Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
        // 套用部分失败留下的原值也必须在主动断开后恢复。
        await controller.DisconnectAsync();
        Assert.Equal("env-restore", order.Last());
    }

    [Fact]
    public async Task ReconnectingKeepsEnvironmentWithoutSecondApply()
    {
        var order = new List<string>();
        var timers = new Timers();
        var tunnel = new ObservableTunnel(order);
        using var controller = EnvironmentController(order, new FakeEnvironment(order), new MemoryEnvironmentSettings(), tunnel, timers);
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        tunnel.Crash();
        await FireAndPublish(controller, timers, "", TimeSpan.Zero);
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.DoesNotContain("env-restore", order);
        await FireAndPublish(controller, timers, "退避", TimeSpan.FromSeconds(2));
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(1, order.Count(x => x == "env-apply"));
    }

    [Fact]
    public async Task EnvironmentToggleAppliesOnlyWhenConnectedAndRestoresImmediately()
    {
        var order = new List<string>();
        var settings = new MemoryEnvironmentSettings { Enabled = false };
        using var controller = EnvironmentController(order, new FakeEnvironment(order), settings);
        await controller.ConnectAsync();
        Assert.DoesNotContain("env-apply", order);
        Assert.Equal("未启用", controller.Snapshot.EnvironmentStatus);
        Assert.False(controller.Snapshot.EnvironmentEnabled);
        await controller.SetEnvironmentEnabledAsync(true);
        Assert.Equal("env-apply", order.Last());
        await controller.SetEnvironmentEnabledAsync(false);
        Assert.Equal("env-restore", order.Last());
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal("未启用", controller.Snapshot.EnvironmentStatus);
        await controller.DisconnectAsync();
        await controller.SetEnvironmentEnabledAsync(true);
        Assert.Equal(1, order.Count(x => x == "env-apply"));
        Assert.Equal("未应用", controller.Snapshot.EnvironmentStatus);
    }

    [Fact]
    public async Task EnvironmentRestoreFailureDoesNotUndoCompletedDisconnect()
    {
        var order = new List<string>();
        var env = new FakeEnvironment(order) { RestoreError = new IOException("模拟恢复失败") };
        using var controller = EnvironmentController(order, env, new MemoryEnvironmentSettings());
        await controller.ConnectAsync();
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Contains("未能恢复", controller.Snapshot.Message);
        Assert.Contains("恢复失败", controller.Snapshot.EnvironmentStatus);
        Assert.Equal(new[] { "apply", "start", "env-apply", "stop", "remove", "env-restore" }, order);
        Assert.True(env.HasPendingState);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StartupEnvironmentFollowsProtectionBranch(bool keep)
    {
        var order = new List<string>();
        var env = new FakeEnvironment(order) { HasPendingState = true };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            environment: env, environmentSettings: new MemoryEnvironmentSettings());
        await controller.InitializeAsync(autoConnect: false, keepProtection: keep);
        if (keep)
        {
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal(new[] { "apply", "start" }, order);
            await controller.DisconnectAsync();
            Assert.Equal("env-restore", order.Last());
        }
        else Assert.Equal(new[] { "recover", "env-restore" }, order);
    }

    [Fact]
    public async Task StartupEnvironmentRestoreFailureStillAutoConnectsAndRetainsWarning()
    {
        var order = new List<string>();
        var env = new FakeEnvironment(order) { HasPendingState = true, RestoreError = new IOException("模拟恢复失败") };
        using var controller = EnvironmentController(order, env, new MemoryEnvironmentSettings());
        await controller.InitializeAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("启动时未能恢复", controller.Snapshot.Message);
        Assert.Equal(new[] { "recover", "env-restore", "apply", "start", "env-apply" }, order);
    }

    [Fact]
    public async Task MissingEnvironmentOnlyPersistsSwitchAndDisposeNeverRestores()
    {
        var order = new List<string>();
        var settings = new MemoryEnvironmentSettings();
        using (var controller = EnvironmentController(order, null, settings))
        {
            await controller.SetEnvironmentEnabledAsync(false);
            Assert.False(settings.Enabled);
            Assert.False(controller.Snapshot.EnvironmentEnabled);
        }
        var active = EnvironmentController(order, new FakeEnvironment(order), new MemoryEnvironmentSettings());
        await active.ConnectAsync();
        active.Dispose();
        Assert.DoesNotContain("env-restore", order);
    }

    private static ClientController EnvironmentController(List<string> order, IEnvironmentEnforcer? environment,
        IEnvironmentSettingsStore settings, ITunnelTransport? tunnel = null, Timers? timers = null,
        IBrowserProcessProbe? browserProbe = null)
    {
        timers ??= new Timers();
        return new ClientController(new PairingSessionSource(PairingTests.ValidPairing()), new Firewall(order),
            tunnel ?? new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay,
            environment: environment, environmentSettings: settings, browserProbe: browserProbe) { DelayWithPurposeAsync = timers.Delay };
    }

    private sealed class FakeEnvironment(List<string> order) : IEnvironmentEnforcer
    {
        public List<EnvironmentTarget> Targets { get; } = [];
        public bool HasPendingState { get; set; }
        public Exception? ApplyError { get; set; }
        public Exception? RestoreError { get; set; }
        public Task ApplyAsync(EnvironmentTarget target)
        { order.Add("env-apply"); Targets.Add(target); HasPendingState = true; if (ApplyError is not null) throw ApplyError; return Task.CompletedTask; }
        public Task<EnvironmentInspection?> InspectAsync() => Task.FromResult<EnvironmentInspection?>(
            EnvironmentSelfCheckTests.GoodInspection with { TimeZone = Targets.Last().TimeZoneId });
        public Task RestoreAsync()
        { order.Add("env-restore"); if (RestoreError is not null) throw RestoreError; HasPendingState = false; return Task.CompletedTask; }
    }

    private sealed class MemoryEnvironmentSettings : IEnvironmentSettingsStore
    {
        public bool Enabled { get; set; } = true;
        public EnvironmentPolicy Read() => new(Enabled, new("AUS Eastern Standard Time", ["en-AU", "en"]));
        public void WriteEnabled(bool enabled) => Enabled = enabled;
    }

    [Theory]
    [InlineData("192.0.2.5", "已核验")]
    [InlineData("198.51.100.9", "不一致")]
    public async Task ExitProbeWaitsThreeSecondsAndNeverDisconnects(string address, string status)
    {
        var probe = new ScriptedProbe(IPAddress.Parse(address));
        var (controller, timers, firewall, order) = await ConnectMonitored(probe);
        using (controller)
        {
            Assert.Equal("核验中", controller.Snapshot.ExitStatus);
            Assert.Equal(0, probe.Calls);
            Assert.Equal(TimeSpan.FromSeconds(3), Assert.Single(timers.For("出口核验")));
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
            Assert.Equal(status, controller.Snapshot.ExitStatus);
            Assert.Equal(address, controller.Snapshot.ExitIp);
            if (status == "不一致") Assert.Contains("不一致", controller.Snapshot.Message);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.DoesNotContain("stop", order);
            Assert.DoesNotContain("remove", order);
            Assert.Empty(firewall.PatrolCalls);
            Assert.Contains(TimeSpan.FromMinutes(5), timers.For("出口核验"));
            await controller.DisconnectAsync();
            Assert.Equal("未检测", controller.Snapshot.ExitStatus);
            Assert.Equal("", controller.Snapshot.ExitIp);
            Assert.Equal("", controller.Snapshot.GuardStatus);
        }
    }

    [Fact]
    public async Task FiveNullProbesRetryEveryFiveSecondsThenRecheckAfterOneMinute()
    {
        var probe = new ScriptedProbe(null, null, null, null, null, IPAddress.Parse(TestData.Node().Host));
        var (controller, timers, _, order) = await ConnectMonitored(probe);
        using (controller)
        {
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
            for (var attempt = 1; attempt < 5; attempt++)
            {
                Assert.Equal("核验中", controller.Snapshot.ExitStatus);
                await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(5));
            }
            Assert.Equal(5, probe.Calls);
            Assert.Equal("无法核验", controller.Snapshot.ExitStatus);
            Assert.Equal("", controller.Snapshot.ExitIp);
            Assert.Equal(4, timers.For("出口核验").Count(d => d == TimeSpan.FromSeconds(5)));
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromMinutes(1));
            Assert.Equal("已核验", controller.Snapshot.ExitStatus);
            Assert.Equal(TestData.Node().Host, controller.Snapshot.ExitIp);
            Assert.Equal(new[] { "apply", "start" }, order);
        }
    }

    [Fact]
    public async Task NullProbeSchedulesNoExitChecks()
    {
        var (controller, timers, _, _) = await ConnectMonitored(null);
        using (controller)
        {
            Assert.Empty(timers.For("出口核验"));
            Assert.Equal("未检测", controller.Snapshot.ExitStatus);
            await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
            Assert.Empty(timers.For("出口核验"));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PatrolUsesModeSpecificRulesAfterSixtySeconds(bool authMode)
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        ISessionSource source = authMode ? new AuthServerSessionSource(new AuthApiClient(http), store)
            : new PairingSessionSource(PairingTests.ValidPairing());
        using var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await controller.ConnectAsync();
        await controller.RefreshSessionAsync();
        Assert.Empty(firewall.PatrolCalls);
        Assert.Equal(TimeSpan.FromSeconds(60), Assert.Single(timers.For("巡检")));
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        var rules = Assert.Single(firewall.PatrolCalls);
        Assert.Equal(authMode, rules.Contains("YuanC-KS-Auth"));
        Assert.Equal(authMode ? 7 : 6, rules.Length);
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
        Assert.Equal(2, timers.For("巡检").Length);
    }

    [Theory]
    [InlineData("missing", "已重建 1 条本项目规则")]
    [InlineData("profile", "已重新收紧 1 条规则")]
    [InlineData("foreign", "已重新收紧 2 条规则")]
    [InlineData("ineffective", "防火墙")]
    [InlineData("failure", "巡检失败,下一轮重试")]
    [InlineData("rebuild-failure", "巡检失败,下一轮重试")]
    public async Task PatrolRepairsOrWarnsWithoutStoppingAndAlwaysSchedulesNext(string scenario, string expected)
    {
        var (controller, timers, firewall, order) = await ConnectMonitored(null);
        using (controller)
        {
            firewall.PatrolResults.Enqueue(scenario switch
            {
                "missing" or "rebuild-failure" => new PatrolReport([], [], ["YuanC-KS-Tun"]),
                "profile" => new PatrolReport(["Public"], [], []),
                "foreign" => new PatrolReport(["Public"], ["third-party"], []),
                "ineffective" => new FirewallIneffectiveException("防火墙失效"),
                _ => new InvalidOperationException("模拟巡检失败")
            });
            if (scenario == "rebuild-failure") firewall.ReapplyError = new InvalidOperationException("模拟重建失败");
            await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
            Assert.Contains(expected, controller.Snapshot.GuardStatus);
            if (scenario == "ineffective") Assert.Equal(controller.Snapshot.GuardStatus, controller.Snapshot.Message);
            Assert.Equal(scenario is "missing" or "rebuild-failure" ? 2 : 1, order.Count(x => x == "apply"));
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.DoesNotContain("stop", order);
            Assert.DoesNotContain("remove", order);
            await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
            Assert.Equal(2, firewall.PatrolCalls.Count);
            Assert.Equal("正常", controller.Snapshot.GuardStatus);
            await controller.DisconnectAsync();
            Assert.Equal("", controller.Snapshot.GuardStatus);
        }
    }

    [Fact]
    public async Task DisconnectedTimersCannotProbeOrPatrolEvenAfterTenMinutes()
    {
        var probe = new ScriptedProbe(IPAddress.Parse(TestData.Node().Host));
        var (controller, timers, firewall, _) = await ConnectMonitored(probe);
        using (controller)
        {
            await controller.DisconnectAsync();
            timers.Advance(TimeSpan.FromMinutes(10));
            await controller.ConnectAsync();
            // 再连接必须重新安排首探与巡检，旧生命周期不得执行。
            Assert.Equal(0, probe.Calls);
            Assert.Empty(firewall.PatrolCalls);
            Assert.Equal(2, timers.For("出口核验").Length);
            Assert.Equal(2, timers.For("巡检").Length);
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
            Assert.Equal(1, probe.Calls);
            await controller.DisconnectAsync();
            timers.Advance(TimeSpan.FromMinutes(10));
            Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
            Assert.Equal("未检测", controller.Snapshot.ExitStatus);
            Assert.Equal("", controller.Snapshot.ExitIp);
            Assert.Empty(firewall.PatrolCalls);
        }
    }

    [Fact]
    public async Task ReconnectKeepsOnePatrolAndInvalidatesPreviousExitCycle()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var tunnel = new ObservableTunnel(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        var probe = new ScriptedProbe(IPAddress.Parse(TestData.Node().Host), IPAddress.Parse(TestData.Node().Host));
        using var controller = new ClientController(source, firewall, tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: probe) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        tunnel.Crash();
        await FireAndPublish(controller, timers, "", TimeSpan.Zero);
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.Equal("未检测", controller.Snapshot.ExitStatus);
        Assert.Equal("", controller.Snapshot.ExitIp);
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Single(firewall.PatrolCalls);
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        await FireAndPublish(controller, timers, "退避", TimeSpan.FromSeconds(2));
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal("核验中", controller.Snapshot.ExitStatus);
        Assert.Equal(2, timers.For("巡检").Length);
        // 上一轮连接遗留的五分钟回调不能提前探测，也不能续排第二条链。
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromMinutes(5));
        Assert.Equal(1, probe.Calls);
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        Assert.Equal(2, probe.Calls);
        Assert.Equal("已核验", controller.Snapshot.ExitStatus);
        Assert.DoesNotContain("remove", order);
    }

    [Theory]
    [InlineData("expiry", ConnectionState.NeedsLogin)]
    [InlineData("rejection", ConnectionState.NeedsLogin)]
    [InlineData("failure", ConnectionState.NeedsManual)]
    public async Task LeavingConnectedClearsExitEvenWhenStoppingThrows(string reason, ConnectionState expected)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        var tunnel = new ObservableTunnel(order);
        var probe = new ScriptedProbe(IPAddress.Parse(TestData.Node().Host));
        using var controller = new ClientController(source, new Firewall(order), tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: probe) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(3));
        if (reason == "expiry")
        {
            var published = Volatile.Read(ref timers.Published);
            timers.Fire("到期", _ => true);
            await Until(() => Volatile.Read(ref timers.Published) > published);
            await controller.RefreshSessionAsync(); // 等迁移回调释放串行锁，不触发重新连接。
        }
        else
        {
            source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.InvalidToken));
            tunnel.FailStop = reason == "failure";
            await controller.RefreshSessionAsync();
        }
        Assert.Equal(expected, controller.Snapshot.State);
        Assert.Equal("未检测", controller.Snapshot.ExitStatus);
        Assert.Equal("", controller.Snapshot.ExitIp);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task ReconnectingWithoutSessionSkipsMissingRuleRebuildAndKeepsPatrolling()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { HasPendingState = true };
        using var http = new HttpClient(new AuthTests.Handler(_ => throw new HttpRequestException()))
        { BaseAddress = new("https://192.0.2.1") };
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), store),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.InitializeAsync(true, true);
        firewall.PatrolResults.Enqueue(new PatrolReport([], [], ["YuanC-KS-Tun"]));
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.Equal("巡检失败,下一轮重试", controller.Snapshot.GuardStatus);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("remove", order);
        Assert.Equal(2, timers.For("巡检").Length);
    }

    private sealed class ObservableTunnel(List<string> order) : ITunnelTransport
    {
        public bool FailStop { get; set; }
        public event EventHandler? TunnelDown;
        public void Crash() => TunnelDown?.Invoke(this, EventArgs.Empty);
        public Task StartAsync(JsonElement configuration, CancellationToken token) { order.Add("start"); return Task.CompletedTask; }
        public void Stop() { order.Add("stop"); if (FailStop) throw new IOException("模拟停止失败"); }
        public void Dispose() { }
    }

    private static async Task<(ClientController Controller, Timers Timers, Firewall Firewall, List<string> Order)> ConnectMonitored(IExitProbe? probe)
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session())); source.Enqueue(Ok(TestData.Session()));
        var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: probe) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        return (controller, timers, firewall, order);
    }

    private static async Task FireAndPublish(ClientController controller, Timers timers, string purpose, TimeSpan duration)
    {
        var published = Volatile.Read(ref timers.Published);
        timers.Fire(purpose, d => d == duration);
        await Until(() => Volatile.Read(ref timers.Published) > published);
        await controller.ConnectAsync(); // 串行锁屏障，等待本次回调完成。
    }

    private static async Task FireParkedPatrol(ClientController controller, Timers timers)
    {
        var published = Volatile.Read(ref timers.Published);
        timers.Fire("巡检", d => d == TimeSpan.FromSeconds(60));
        await Until(() => Volatile.Read(ref timers.Published) > published);
        await controller.RefreshSessionAsync(); // 串行锁屏障;没连着时它什么都不做。
    }

    /// <summary>触发地址变化后的网卡收紧等待;触发后会停住或回到未连接的用它,屏障用 RefreshSessionAsync。</summary>
    private static async Task FireNicSweep(ClientController controller, Timers timers)
    {
        var published = Volatile.Read(ref timers.Published);
        timers.Fire("网卡收紧", d => d == ClientController.NicSweepDelay);
        await Until(() => Volatile.Read(ref timers.Published) > published);
        await controller.RefreshSessionAsync(); // 串行锁屏障;没连着时它什么都不做。
    }

    /// <summary>第一次启动抛「找不到内核」,之后成功。</summary>
    private sealed class FirstStartMissingTunnel(List<string> order) : ITunnelTransport
    {
        private int starts;
        public event EventHandler? TunnelDown { add { } remove { } }
        public Task StartAsync(JsonElement configuration, CancellationToken token)
        {
            order.Add("start");
            if (Interlocked.Increment(ref starts) == 1) throw new FileNotFoundException("测试:找不到内核");
            return Task.CompletedTask;
        }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }

    /// <summary>第一次启动抛 IOException(模拟断网),之后成功;用来停在首次尝试的退避里。</summary>
    private sealed class FirstStartBrokenTunnel(List<string> order) : ITunnelTransport
    {
        private int starts;
        public event EventHandler? TunnelDown { add { } remove { } }
        public Task StartAsync(JsonElement configuration, CancellationToken token)
        {
            order.Add("start");
            if (Interlocked.Increment(ref starts) == 1) throw new IOException("测试断网");
            return Task.CompletedTask;
        }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnverifiableExitShowsHintAfterFirstRoundWithoutDisconnecting(bool pairing)
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        ISessionSource source = pairing ? new PairingSessionSource(PairingTests.ValidPairing())
            : new AuthServerSessionSource(new AuthApiClient(http), store);
        var probe = new ScriptedProbe(Enumerable.Repeat<IPAddress?>(null, 20)
            .Append(IPAddress.Parse(pairing ? PairingTests.ValidPairing().Node.Host : TestData.Node().Host)).ToArray());
        using var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, exitProbe: probe) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        for (var round = 0; round < 4; round++)
        {
            await CompleteUnverifiableRound(controller, timers, round == 0 ? TimeSpan.FromSeconds(3) : TimeSpan.FromMinutes(1));
            Assert.Equal(pairing ? ClientController.PairingUnverifiableHint : ClientController.AuthUnverifiableHint,
                controller.Snapshot.Message);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.Equal("无法核验", controller.Snapshot.ExitStatus);
            Assert.DoesNotContain("stop", order);
            Assert.DoesNotContain("remove", order);
        }
        await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromMinutes(1));
        Assert.Equal("已核验", controller.Snapshot.ExitStatus);
        Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
    }

    [Fact]
    public async Task UnverifiableExitRechecksEveryMinuteUntilVerified()
    {
        var probe = new ScriptedProbe(Enumerable.Repeat<IPAddress?>(null, 10)
            .Append(IPAddress.Parse(TestData.Node().Host)).ToArray());
        var (controller, timers, _, _) = await ConnectMonitored(probe);
        using (controller)
        {
            await CompleteUnverifiableRound(controller, timers, TimeSpan.FromSeconds(3));
            Assert.Equal(TimeSpan.FromMinutes(1), timers.For("出口核验").Last());
            await CompleteUnverifiableRound(controller, timers, TimeSpan.FromMinutes(1));
            Assert.Equal(TimeSpan.FromMinutes(1), timers.For("出口核验").Last());
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromMinutes(1));
            Assert.Equal("已核验", controller.Snapshot.ExitStatus);
            Assert.Equal(TimeSpan.FromMinutes(5), timers.For("出口核验").Last());
        }
    }

    [Fact]
    public async Task UnverifiableCounterResetsWhenExitRecovers()
    {
        var probe = new ScriptedProbe(Enumerable.Repeat<IPAddress?>(null, 5)
            .Append(IPAddress.Parse(TestData.Node().Host)).Concat(Enumerable.Repeat<IPAddress?>(null, 5)).ToArray());
        var (controller, timers, _, _) = await ConnectMonitored(probe);
        using (controller)
        {
            await CompleteUnverifiableRound(controller, timers, TimeSpan.FromSeconds(3));
            Assert.Equal(ClientController.AuthUnverifiableHint, controller.Snapshot.Message);
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromMinutes(1));
            Assert.Equal("已核验", controller.Snapshot.ExitStatus);
            Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
            Assert.Equal(TimeSpan.FromMinutes(5), timers.For("出口核验").Last());
            await CompleteUnverifiableRound(controller, timers, TimeSpan.FromMinutes(5));
            Assert.Equal(ClientController.AuthUnverifiableHint, controller.Snapshot.Message);
        }
    }

    private static async Task CompleteUnverifiableRound(ClientController controller, Timers timers, TimeSpan firstWait)
    {
        await FireAndPublish(controller, timers, "出口核验", firstWait);
        for (var attempt = 1; attempt < 5; attempt++)
            await FireAndPublish(controller, timers, "出口核验", TimeSpan.FromSeconds(5));
        Assert.Equal("无法核验", controller.Snapshot.ExitStatus);
    }

    private static async Task<(ClientController Controller, Timers Timers, Firewall Firewall)> ConnectWithJournal(
        Firewall firewall, System.Collections.Concurrent.ConcurrentQueue<string> journal)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource();
        source.Enqueue(Ok(TestData.Session()));
        source.Enqueue(Ok(TestData.Session()));
        var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay, Journal = line => journal.Enqueue(line) };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        return (controller, timers, firewall);
    }

    [Fact]
    public async Task DisconnectWithoutRecordShowsWindowsDefaultWarning()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { LastRemoveWarning = KillSwitchApplier.NoRecordRemoveWarning };
        var journal = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var (controller, _, _) = await ConnectWithJournal(firewall, journal);
        using (controller)
        {
            await controller.DisconnectAsync();
            Assert.Equal("已断开。" + KillSwitchApplier.NoRecordRemoveWarning, controller.Snapshot.Message);
            Assert.Contains(journal, line => line.Contains("撤销断网保护：没有恢复记录，默认出站已按 Windows 默认改回允许"));
        }
    }

    [Fact]
    public async Task DisconnectWithRecordKeepsRestoredMessage()
    {
        var order = new List<string>();
        var firewall = new Firewall(order);
        var journal = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var (controller, _, _) = await ConnectWithJournal(firewall, journal);
        using (controller)
        {
            await controller.DisconnectAsync();
            Assert.Equal("已断开，原网络设置已恢复。", controller.Snapshot.Message);
            Assert.DoesNotContain(journal, line => line.Contains("撤销断网保护：没有恢复记录，默认出站已按 Windows 默认改回允许"));
        }
    }

    [Fact]
    public async Task AbandonWithoutRecordAppendsWindowsDefaultWarning()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { LastRemoveWarning = KillSwitchApplier.NoRecordRemoveWarning };
        var probe = new ScriptedProbe(Enumerable.Repeat<IPAddress?>(null, 6).ToArray());
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay, exitProbe: probe)
            { DelayWithPurposeAsync = timers.Delay, TestBuild = true };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        await FireExitChecksUntilAbandon(controller, timers, probe);
        Assert.StartsWith("测试包：出口核验不了，已自动断开并恢复原来的网络。", controller.Snapshot.Message);
        Assert.Contains(KillSwitchApplier.NoRecordRemoveWarning, controller.Snapshot.Message);
    }

    /// <summary>逐轮触发出口核验,直到测试包自动断开;断开时状态先变、消息后写,所以等到放弃消息落定。</summary>
    private static async Task FireExitChecksUntilAbandon(ClientController controller, Timers timers, ScriptedProbe probe)
    {
        while (controller.Snapshot.State != ConnectionState.Disconnected)
        {
            var calls = probe.Calls;
            var before = timers.For("出口核验").Length;
            timers.Fire("出口核验", _ => true);
            await Until(() => probe.Calls > calls || controller.Snapshot.State == ConnectionState.Disconnected);
            if (controller.Snapshot.State == ConnectionState.Disconnected) break;
            await Until(() => controller.Snapshot.State == ConnectionState.Disconnected || timers.For("出口核验").Length > before);
        }
        await Until(() => controller.Snapshot.State == ConnectionState.Disconnected &&
            controller.Snapshot.Message.StartsWith("测试包：", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DisconnectCancelsRunningPatrolAndFinishesPromptly()
    {
        var (controller, timers, firewall, order) = await ConnectMonitored(null);
        using (controller)
        {
            firewall.BlockPatrol = true;
            timers.Fire("巡检", d => d == TimeSpan.FromSeconds(60));
            await firewall.PatrolStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await controller.DisconnectAsync().WaitAsync(TimeSpan.FromSeconds(2));
            Assert.True(firewall.PatrolToken.IsCancellationRequested);
            Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
            Assert.Contains("remove", order);
            Assert.Equal("", controller.Snapshot.GuardStatus);
            Assert.Single(timers.For("巡检"));
        }
    }

    private sealed class ScriptedProbe(params IPAddress?[] results) : IExitProbe
    {
        private readonly Queue<IPAddress?> results = new(results);
        public int Calls { get; private set; }
        public Task<IPAddress?> ProbeAsync(CancellationToken token)
        {
            Calls++;
            return Task.FromResult(results.Dequeue());
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StartupKeepsPairingProtectionAndConnectsRegardlessOfAutoConnect(bool autoConnect)
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        var snapshots = new List<ClientSnapshot>();
        controller.Changed += snapshots.Add;
        await controller.InitializeAsync(autoConnect, keepProtection: true);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("保持", controller.Snapshot.Message);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains(snapshots, snapshot => snapshot.Message == "后台服务已重新启动，断网保护保持，正在恢复连接。");
        Assert.All(snapshots, snapshot => Assert.True(snapshot.ProtectionActive));
    }

    [Fact]
    public async Task StartupKeptWithoutServerParksWithProtection()
    {
        var order = new List<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ClientController.KeptWithoutPairingMessage, controller.Snapshot.Message);
    }

    [Fact]
    public async Task StartupKeptWithoutCredentialsParksWithProtection()
    {
        var order = new List<string>();
        using var http = new HttpClient(new AuthTests.Handler(_ => throw new InvalidOperationException("不应请求会话")))
        { BaseAddress = new("https://192.0.2.1") };
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), new InMemoryCredentialStore()),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ClientController.KeptWithoutCredentialsMessage, controller.Snapshot.Message);
    }

    /// <summary>读取凭据时抛异常的假件:验证启动时凭据读不出来也按「找不到」停在需人工处理。</summary>
    private sealed class ThrowingCredentialStore : ICredentialStore
    {
        public void Save(string refreshToken) { }
        public string? Load() => throw new IOException("测试:凭据读不出来");
        public void Clear() { }
    }

    [Fact]
    public async Task StartupKeptCredentialReadFailureParksWithProtection()
    {
        var order = new List<string>();
        using var http = new HttpClient(new AuthTests.Handler(_ => throw new InvalidOperationException("不应请求会话")))
        { BaseAddress = new("https://192.0.2.1") };
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), new ThrowingCredentialStore()),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ClientController.KeptWithoutCredentialsMessage, controller.Snapshot.Message);
    }

    [Fact]
    public async Task StartupKeptParkedDisconnectRestoresNetwork()
    {
        var order = new List<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        await controller.DisconnectAsync();
        Assert.Contains("remove", order);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.StartsWith("已断开", controller.Snapshot.Message);
    }

    [Fact]
    public async Task StartupKeptParkedConnectKeepsGuidance()
    {
        var order = new List<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(ClientController.KeptWithoutPairingMessage, controller.Snapshot.Message);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task StartupKeptParkedWritesJournalLine()
    {
        var order = new List<string>();
        var journal = new System.Collections.Concurrent.ConcurrentQueue<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device)
            { Journal = journal.Enqueue };
        await controller.InitializeAsync(true, true);
        var lines = journal.ToArray();
        Assert.Contains("启动：找不到配对文件或登录凭据，断网保护保持，停在需人工处理", lines);
        Assert.DoesNotContain(lines, line => line.StartsWith("启动：已做启动恢复", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartupKeptWithoutRecordStillRecovers()
    {
        var order = new List<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.Equal(new[] { "recover" }, order);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.Contains("未配置服务器", controller.Snapshot.Message);
    }

    [Fact]
    public async Task StartupKeptFlagOffStillRecovers()
    {
        var order = new List<string>();
        using var controller = new ClientController((ISessionSource?)null,
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, false);
        Assert.Equal(new[] { "recover" }, order);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
    }

    [Fact]
    public async Task StartupWithoutPendingStateStillRecoversThenAutomaticallyConnects()
    {
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(true, true);
        Assert.Equal(new[] { "recover", "apply", "start" }, order);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OnlyAuthModePassesAuthEndpointToFirewall(bool authMode)
    {
        var order = new List<string>();
        var firewall = new Firewall(order);
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        ISessionSource source = authMode ? new AuthServerSessionSource(new AuthApiClient(http), store)
            : new PairingSessionSource(PairingTests.ValidPairing());
        var endpoint = new AuthEndpoint(IPAddress.Parse("192.0.2.1"), 8443, Path.GetFullPath("service.exe"));
        using var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, authEndpoint: endpoint);
        await controller.ConnectAsync();
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.Equal(authMode ? endpoint : null, firewall.AppliedAuth);
    }

    [Fact]
    public async Task StartupAuthNetworkRetriesExhaustWithoutEverRemovingProtection()
    {
        var timers = new Timers();
        var order = new List<string>();
        var calls = 0;
        using var http = new HttpClient(new AuthTests.Handler(_ =>
        { Interlocked.Increment(ref calls); throw new HttpRequestException("测试网络不可达"); }))
        { BaseAddress = new("https://192.0.2.1") };
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthServerSessionSource(new AuthApiClient(http), store),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        var snapshots = new System.Collections.Concurrent.ConcurrentQueue<ClientSnapshot>();
        var manual = new TaskCompletionSource<ClientSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.Changed += snapshot =>
        {
            snapshots.Enqueue(snapshot);
            if (snapshot.State == ConnectionState.NeedsManual && snapshot.Message.Contains("多次重连仍未成功")) manual.TrySetResult(snapshot);
        };
        await controller.InitializeAsync(true, true);
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60 })
        {
            var scheduled = await timers.TakeAsync("退避", timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            scheduled.Completion.SetResult();
        }
        var result = await manual.Task.WaitAsync(timeout.Token);
        Assert.Equal(ConnectionState.NeedsManual, result.State);
        Assert.True(result.ProtectionActive);
        Assert.All(snapshots, snapshot => Assert.True(snapshot.ProtectionActive));
        Assert.Equal(12, Volatile.Read(ref calls));
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
    }

    [Fact]
    public async Task RecoveryWarningRemainsVisibleAfterAutomaticConnect()
    {
        var order = new List<string>();
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        const string warning = "上次断网保护已降级恢复，请管理员检查记录。";
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { RecoveryWarning = warning }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Contains(warning, controller.Snapshot.Message);
        Assert.NotEqual(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(order.IndexOf("recover") >= 0 && order.IndexOf("apply") > order.IndexOf("recover"));
        Assert.Contains("start", order);
    }

    [Fact]
    public async Task RecoveryWarningAlsoExplainsMissingServer()
    {
        var order = new List<string>();
        const string warning = "上次断网保护已降级恢复。";
        using var controller = new ClientController(null, new InMemoryCredentialStore(),
            new Firewall(order) { RecoveryWarning = warning }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(warning + " 未配置服务器。", controller.Snapshot.Message);
        Assert.NotEqual(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.DoesNotContain("apply", order);
    }

    [Fact]
    public async Task FailedRecoveryNeedsManualAndExplainsPreservedRecord()
    {
        var order = new List<string>();
        using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { FailRecovery = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Contains("恢复记录已保留", controller.Snapshot.Message);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("start", order);
    }

    [Fact]
    public async Task PairingRetriesReachManualWithAddressHintAndKeepProtection()
    {
        var timers = new Timers();
        var expiryTokens = new List<CancellationToken>();
        Task Delay(TimeSpan duration, CancellationToken token, string purpose)
        {
            if (purpose == "到期") expiryTokens.Add(token);
            return timers.Delay(duration, token, purpose);
        }
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order) { HasPendingState = true }, new PairingTests.FakeTunnel(order, fail: true), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = Delay };
        var manual = new TaskCompletionSource<ClientSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.Changed += snapshot => { if (snapshot.State == ConnectionState.NeedsManual && snapshot.Message.Contains("出口地址可能已变")) manual.TrySetResult(snapshot); };
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (var seconds in new[] { 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60 })
        {
            var scheduled = await timers.TakeAsync("退避", timeout.Token);
            Assert.Equal(TimeSpan.FromSeconds(seconds), scheduled.Delay);
            scheduled.Completion.SetResult();
        }
        var result = await manual.Task.WaitAsync(timeout.Token);
        Assert.Equal(ConnectionState.NeedsManual, result.State);
        Assert.Contains("出口地址可能已变", result.Message);
        Assert.Contains("重新导出配对文件再导入", result.Message);
        Assert.True(result.ProtectionActive);
        Assert.Equal(12, order.Count(x => x == "start"));
        Assert.DoesNotContain("remove", order);
        var previousExpiry = Assert.Single(expiryTokens);
        await controller.ConnectAsync();
        Assert.True(previousExpiry.IsCancellationRequested);
        Assert.Equal(2, expiryTokens.Count);
    }
    [Fact]
    public async Task StartupRecoveryPrecedesConnectAndNodeChangeNeverRestores()
    {
        var order = new List<string>(); var host = "192.0.2.5";
        using var http = SessionHttp(() => TestData.Session(host));
        var firewall = new Firewall(order); var tunnel = new Tunnel(order);
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store, firewall, tunnel, Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync();
        Assert.Equal(new[] { "recover", "apply", "start" }, order);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        host = "192.0.2.6";
        await controller.RefreshSessionAsync();
        Assert.Contains("update:192.0.2.6", order);
        Assert.DoesNotContain("remove", order);
        Assert.True(controller.Snapshot.ProtectionActive);
        await controller.DisconnectAsync();
        Assert.Equal("remove", order.Last());
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
    }
    [Fact]
    public async Task RejectedSessionNeverStartsTunnel()
    {
        var order = new List<string>();
        using var http = new HttpClient(new AuthTests.Handler(_ => new(HttpStatusCode.Forbidden))) { BaseAddress = new("https://unit.invalid") };
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store, new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.DoesNotContain("start", order); Assert.DoesNotContain("apply", order); Assert.DoesNotContain("remove", order);
    }
    [Fact]
    public async Task ApplyFailureOnFirstConnectRestoresNetworkWithoutStartingTunnel()
    {
        var order = new List<string>(); using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store, new Firewall(order) { FailApply = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.StartsWith("连接失败，已恢复原来的网络，当前没有走澳洲出口。", controller.Snapshot.Message);
        Assert.DoesNotContain("start", order);
        Assert.Contains("remove", order);
    }
    [Fact]
    public async Task IneffectiveFirewallOnFirstConnectRestoresNetworkAndNamesReason()
    {
        var order = new List<string>(); using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        const string explanation = "系统防火墙被策略覆盖，请断开后联系管理员。";
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { ApplyError = new FirewallIneffectiveException(explanation) },
            new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal("连接失败，已恢复原来的网络，当前没有走澳洲出口。原因：系统防火墙没有开启，或被策略覆盖。", controller.Snapshot.Message);
        Assert.Contains("apply", order);
        Assert.DoesNotContain("start", order);
        Assert.Contains("remove", order);
    }
    [Fact]
    public async Task HeldProtectionStartupKeepsTunnelAndWarnsWhenFirewallIsIneffective()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true, ApplyError = new FirewallIneffectiveException("模拟") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);

        await controller.InitializeAsync(autoConnect: false, keepProtection: true);

        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.GuardStatus);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.Message);
        Assert.DoesNotContain("stop", order);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task HeldAppsProtectionStartupKeepsTunnelAndWarnsWhenFirewallIsIneffective()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true, PendingMode = "apps",
            ApplyAppsError = new FirewallIneffectiveException("模拟") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, routingSettings: new MemoryRouting());

        await controller.InitializeAsync(autoConnect: false, keepProtection: true);

        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply-apps", "start" }, order);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.GuardStatus);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.Message);
        Assert.DoesNotContain("stop", order);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task ReauthenticationKeepsTunnelAndWarnsWhenHeldProtectionCannotBeReapplied()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, firewall, new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);

        firewall.ApplyError = new FirewallIneffectiveException("模拟");
        source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.Network));
        await controller.RefreshSessionAsync();
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        source.Enqueue(Ok(TestData.Session()));
        await FireAndPublish(controller, timers, "退避", TimeSpan.FromSeconds(2));

        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(new[] { "apply", "start", "stop", "apply", "start" }, order);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.GuardStatus);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.Message);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task IneffectiveFirewallOnRepeatedFirstConnectRestoresEachTime()
    {
        var order = new List<string>();
        const string explanation = "系统防火墙被策略覆盖，请断开后联系管理员。";
        var firewall = new Firewall(order) { ApplyError = new FirewallIneffectiveException(explanation) };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            await controller.ConnectAsync();
            Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
            Assert.False(controller.Snapshot.ProtectionActive);
            Assert.Equal("连接失败，已恢复原来的网络，当前没有走澳洲出口。原因：系统防火墙没有开启，或被策略覆盖。", controller.Snapshot.Message);
            Assert.DoesNotContain("start", order);
        }
        Assert.Equal(2, order.Count(item => item == "apply"));
        Assert.Equal(2, order.Count(item => item == "remove"));
    }

    [Fact]
    public async Task SuccessfulPatrolClearsHeldProtectionWarningAndDisconnectStillRemovesProtection()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { HasPendingState = true, ApplyError = new FirewallIneffectiveException("模拟") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.Message);

        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));

        Assert.Equal("正常", controller.Snapshot.GuardStatus);
        Assert.Equal("断网保护已重新生效。", controller.Snapshot.Message);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start" }, order);
        await controller.DisconnectAsync();
        Assert.Equal(new[] { "stop", "remove" }, order.TakeLast(2));
    }

    [Fact]
    public async Task IneffectivePatrolKeepsHeldTunnelAndExistingPatrolWarning()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { HasPendingState = true, ApplyError = new FirewallIneffectiveException("模拟") };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains("断网保护未能重新套用", controller.Snapshot.Message);
        firewall.PatrolResults.Enqueue(new FirewallIneffectiveException("x"));

        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));

        Assert.Equal("系统防火墙已被关闭或被策略覆盖,断网保护可能失效,请立即在 Windows 安全中心开启防火墙或联系管理员",
            controller.Snapshot.GuardStatus);
        Assert.Equal(controller.Snapshot.GuardStatus, controller.Snapshot.Message);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.DoesNotContain("stop", order);
        Assert.DoesNotContain("remove", order);
    }

    [Fact]
    public async Task MissingServerIsExplicitAndClosingDoesNotRemove()
    {
        var order = new List<string>();
        var controller = new ClientController(null, new InMemoryCredentialStore(), new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(); Assert.Equal("未配置服务器", controller.Snapshot.Message);
        controller.Dispose(); Assert.DoesNotContain("remove", order);
    }
    // ===== 会话续期（邀请码模式）=====

    [Fact]
    public async Task RenewWaitIsScheduledAtEightyPercentAlongsideExpiry()
    {
        var (controller, timers, _, _) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Contains(timers.Delays, d => Near(d, TimeSpan.FromHours(6 * 0.8)));
            Assert.Contains(timers.Delays, d => Near(d, TimeSpan.FromHours(6)));
        }
    }

    [Fact]
    public async Task RenewWithSameContentOnlySwapsSessionWithoutRestartingTunnel()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(7), token: "renewed-session")));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            await Until(() => timers.For("到期", "续期").Length == 4);
            Assert.Equal(new[] { "apply", "start" }, order);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
            Assert.Equal(2, source.Calls);
            // 新会话的到期与续期等待已重新安排，说明控制器持有的会话到期时间已更新。
            Assert.Contains(timers.For("到期", "续期").Skip(2), d => Near(d, TimeSpan.FromHours(7)));
            Assert.Contains(timers.For("到期", "续期").Skip(2), d => Near(d, TimeSpan.FromHours(7 * 0.8)));
            // 旧会话的到期回调触发时不再生效。
            await controller.ConnectAsync(); // 已连接时直接返回，用作串行锁屏障。
            var published = Volatile.Read(ref timers.Published);
            timers.Fire(d => Near(d, TimeSpan.FromHours(6)));
            await Until(() => Volatile.Read(ref timers.Published) > published);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal(new[] { "apply", "start" }, order);
        }
    }

    [Fact]
    public async Task RenewNetworkFailureRetriesEveryFiveMinutesWithoutTouchingTunnel()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.Network));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            await Until(() => timers.For("到期", "续期").Length == 3);
            Assert.Equal(TimeSpan.FromMinutes(5), timers.For("到期", "续期")[2]);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Equal(new[] { "apply", "start" }, order);
            Assert.True(controller.Snapshot.ProtectionActive);
            // 再次触发：服务器恢复，返回内容相同的新会话，回到只换会话的路径。
            source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(7), token: "renewed-session")));
            timers.Fire(d => d == TimeSpan.FromMinutes(5));
            await Until(() => timers.For("到期", "续期").Length == 5);
            Assert.Equal(3, source.Calls);
            Assert.Equal(new[] { "apply", "start" }, order);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.Contains(timers.For("到期", "续期").Skip(3), d => Near(d, TimeSpan.FromHours(7)));
            Assert.Contains(timers.For("到期", "续期").Skip(3), d => Near(d, TimeSpan.FromHours(7 * 0.8)));
        }
    }

    [Fact]
    public async Task RenewRejectedTokenNeedsLoginStopsTunnelAndKeepsProtection()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.InvalidToken));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            await Until(() => controller.Snapshot.State == ConnectionState.NeedsLogin);
            await Until(() => order.Contains("stop"));
            Assert.Equal(new[] { "apply", "start", "stop" }, order);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.DoesNotContain("remove", order);
        }
    }

    [Fact]
    public async Task RenewWithChangedNodeRestartsTunnelUnderProtection()
    {
        var (controller, timers, source, order) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromHours(6)));
        using (controller)
        {
            source.Enqueue(Ok(TestData.SessionExpiringIn(TimeSpan.FromHours(7), token: "renewed-session",
                node: TestData.Node(host: "192.0.2.6"))));
            timers.Fire(d => Near(d, TimeSpan.FromHours(4.8)));
            // 停内核后进入退避，并为新会话安排到期与续期等待。
            await Until(() => timers.For("到期", "续期", "退避").Length == 5);
            Assert.Equal(new[] { "apply", "start", "update", "stop" }, order);
            Assert.True(controller.Snapshot.ProtectionActive);
            timers.Fire(d => d == TimeSpan.FromSeconds(2));
            await Until(() => controller.Snapshot.State == ConnectionState.Connected);
            await controller.ConnectAsync(); // 串行锁屏障，等退避回调结束。
            Assert.Equal(new[] { "apply", "start", "update", "stop", "start" }, order);
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            Assert.True(controller.Snapshot.ProtectionActive);
            Assert.Contains(timers.Delays, d => Near(d, TimeSpan.FromHours(7 * 0.8)));
        }
    }

    [Fact]
    public async Task PairingModeNeverSchedulesRenew()
    {
        var timers = new Timers();
        var order = new List<string>();
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new PairingTests.FakeFirewall(order), new PairingTests.FakeTunnel(order), Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay)
            { DelayWithPurposeAsync = timers.Delay };
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        // 原有会话等待只有到期的第一段（一天）；巡检另按用途检查。
        Assert.Equal(TimeSpan.FromDays(1), Assert.Single(timers.For("到期", "续期")));
        Assert.DoesNotContain(timers.For("到期", "续期"), d => d < TimeSpan.FromDays(1));
        Assert.Equal(TimeSpan.FromSeconds(60), Assert.Single(timers.For("巡检")));
        Assert.Empty(timers.For("续期"));
    }

    [Fact]
    public async Task NoRenewWhenLessThanOneMinuteRemains()
    {
        var (controller, timers, _, _) = await ConnectRenewable(TestData.SessionExpiringIn(TimeSpan.FromSeconds(30)));
        using (controller)
        {
            Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
            var expiry = Assert.Single(timers.For("到期", "续期"));
            Assert.True(expiry <= TimeSpan.FromSeconds(30));
        }
    }

    [Theory]
    [InlineData("host")]
    [InlineData("reality_port")]
    [InlineData("hy2_port")]
    [InlineData("sni")]
    [InlineData("reality_public_key")]
    [InlineData("short_id")]
    [InlineData("uuid")]
    [InlineData("hy2_password")]
    [InlineData("hy2_server_name")]
    [InlineData("hy2_certificate")]
    [InlineData("hy2_obfs_password")]
    public void SameSessionDetectsAnyNodeOrConfigDifference(string field)
    {
        var baseline = TestData.SessionExpiringIn(TimeSpan.FromHours(6));
        var node = field switch
        {
            "host" => TestData.Node(host: "192.0.2.6"),
            "reality_port" => TestData.Node(realityPort: 444),
            "hy2_port" => TestData.Node(hy2Port: 8444),
            "sni" => TestData.Node(sni: "other.invalid"),
            "reality_public_key" => TestData.Node(realityPublicKey: "other-key"),
            "short_id" => TestData.Node(shortId: "other-short"),
            "uuid" => TestData.Node(uuid: "other-uuid"),
            "hy2_password" => TestData.Node(hy2Password: "other-password"),
            "hy2_server_name" => TestData.Node(hy2ServerName: "other-name"),
            "hy2_certificate" => TestData.Node(hy2Certificate: ["-----BEGIN CERTIFICATE-----", "other-cert", "-----END CERTIFICATE-----"]),
            "hy2_obfs_password" => TestData.Node(hy2ObfsPassword: "other-obfs-password"),
            _ => TestData.Node()
        };
        var changed = TestData.SessionExpiringIn(TimeSpan.FromHours(6), node: node);
        Assert.False(ClientController.SameSession(baseline, changed));
    }

    [Fact]
    public void SameSessionIgnoresTokenAndExpiry()
    {
        var a = TestData.SessionExpiringIn(TimeSpan.FromHours(6), token: "first", accountLifetime: TimeSpan.FromDays(1));
        var b = TestData.SessionExpiringIn(TimeSpan.FromHours(9), token: "second", accountLifetime: TimeSpan.FromDays(2));
        Assert.True(ClientController.SameSession(a, b));
    }

    private static bool Near(TimeSpan actual, TimeSpan expected) => (actual - expected).Duration() <= TimeSpan.FromMinutes(2);
    private static AuthResponse<SessionResponse> Ok(SessionResponse value) => new(AuthResult.Ok, value);
    private static async Task Until(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("等待控制器处理超时。");
            await Task.Delay(10);
        }
    }
    private static async Task<(ClientController Controller, Timers Timers, ScriptedSource Source, List<string> Order)> ConnectRenewable(
        SessionResponse first)
    {
        var order = new List<string>();
        var timers = new Timers();
        var source = new ScriptedSource();
        source.Enqueue(Ok(first));
        var controller = new ClientController(source, new PairingTests.FakeFirewall(order), new PairingTests.FakeTunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        return (controller, timers, source, order);
    }
    /// <summary>可脚本化的会话来源：按调用次序返回预设结果；标记为需要续期的来源。</summary>
    private sealed class ScriptedSource : IRenewableSessionSource
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<AuthResponse<SessionResponse>> script = new();
        private int calls;
        public int Calls => Volatile.Read(ref calls);
        public string Mode => "邀请码模式";
        public void Enqueue(AuthResponse<SessionResponse> response) => script.Enqueue(response);
        public Task<AuthResponse<SessionResponse>> GetSessionAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref calls);
            return script.TryDequeue(out var next) ? Task.FromResult(next)
                : throw new InvalidOperationException("测试脚本没有预设下一次会话结果。");
        }
    }
    /// <summary>记录每次等待并返回可手动完成的任务；测试按需触发某个等待。</summary>
    private sealed class Timers
    {
        private readonly List<(TimeSpan Delay, TaskCompletionSource Completion, string Purpose)> entries = [];
        private readonly Dictionary<string, System.Threading.Channels.Channel<(TimeSpan Delay, TaskCompletionSource Completion)>> queues = new();
        public int Published;
        public TimeSpan[] Delays { get { lock (entries) return entries.Select(e => e.Delay).ToArray(); } }
        public int Count { get { lock (entries) return entries.Count; } }
        public TimeSpan[] For(params string[] purposes)
        { lock (entries) return entries.Where(e => purposes.Contains(e.Purpose)).Select(e => e.Delay).ToArray(); }
        public Task Delay(TimeSpan delay, CancellationToken token) => Delay(delay, token, "");
        public Task Delay(TimeSpan delay, CancellationToken token, string purpose)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            token.Register(() => completion.TrySetCanceled(token));
            lock (entries)
            {
                entries.Add((delay, completion, purpose));
                QueueFor(purpose).Writer.TryWrite((delay, completion));
            }
            return completion.Task;
        }
        private System.Threading.Channels.Channel<(TimeSpan Delay, TaskCompletionSource Completion)> QueueFor(string purpose)
        {
            if (!queues.TryGetValue(purpose, out var queue))
                queues[purpose] = queue = System.Threading.Channels.Channel.CreateUnbounded<(TimeSpan, TaskCompletionSource)>();
            return queue;
        }
        public ValueTask<(TimeSpan Delay, TaskCompletionSource Completion)> TakeAsync(string purpose, CancellationToken token)
        { lock (entries) return QueueFor(purpose).Reader.ReadAsync(token); }
        public void Fire(Func<TimeSpan, bool> match)
        {
            TaskCompletionSource target;
            lock (entries) target = entries.First(e => !e.Completion.Task.IsCompleted && match(e.Delay)).Completion;
            target.SetResult();
        }
        public void Fire(string purpose, Func<TimeSpan, bool> match)
        {
            TaskCompletionSource target;
            lock (entries) target = entries.First(e => !e.Completion.Task.IsCompleted && e.Purpose == purpose && match(e.Delay)).Completion;
            target.SetResult();
        }
        public void Advance(TimeSpan duration)
        {
            lock (entries)
                foreach (var entry in entries.Where(e => e.Delay <= duration)) entry.Completion.TrySetResult();
        }
    }

    private static HttpClient SessionHttp(Func<SessionResponse> response) => new(new AuthTests.Handler(_ => new(HttpStatusCode.OK)
    { Content = new StringContent(JsonSerializer.Serialize(response(), new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })) }))
    { BaseAddress = new("https://unit.invalid") };
    [Fact]
    public async Task HeldWfpFailureKeepsTunnelAndShowsExactWarning()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true,
            ApplyError = new WfpUnavailableException(KillSwitchApplier.WfpConnectRefused) };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(new[] { "apply", "start" }, order);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal("断网保护未能重新套用:系统过滤层的过滤器未能建立,隧道保持,但缺少这道断网兜底;请联系管理员", controller.Snapshot.Message);
    }

    [Fact]
    public async Task FirstWfpFailureRestoresNetworkAndNamesReason()
    {
        var order = new List<string>(); using var http = SessionHttp(() => TestData.Session());
        var store = new InMemoryCredentialStore(); store.Save("refresh");
        using var controller = new ClientController(new AuthApiClient(http), store,
            new Firewall(order) { ApplyError = new WfpUnavailableException(KillSwitchApplier.WfpConnectRefused) },
            new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal("连接失败，已恢复原来的网络，当前没有走澳洲出口。原因：系统过滤层的保护没能建立。", controller.Snapshot.Message);
        Assert.Contains("apply", order);
        Assert.DoesNotContain("start", order);
        Assert.Contains("remove", order);
    }

    private sealed class FakeNic(List<string> order) : INicGuard
    {
        public bool HasPendingState { get; set; }
        public string? PublicIpv4 { get; set; }
        public Exception? PublicIpv4Error { get; set; }
        public Exception? ApplyError { get; set; }
        public Exception? PatrolError { get; set; }
        public NicPatrolReport PatrolResult { get; set; } = new([], []);
        public string? RestoreWarning { get; set; }
        public string? PublicIpv4Adapter()
        { order.Add("nic-check"); if (PublicIpv4Error is not null) throw PublicIpv4Error; return PublicIpv4; }
        public Task ApplyAsync(CancellationToken token)
        { order.Add("nic-apply"); return ApplyError is null ? Task.CompletedTask : Task.FromException(ApplyError); }
        public Task<NicPatrolReport> PatrolAsync(CancellationToken token)
        { order.Add("nic-patrol"); return PatrolError is null ? Task.FromResult(PatrolResult) : Task.FromException<NicPatrolReport>(PatrolError); }
        public Task<string?> RestoreAsync() { order.Add("nic-restore"); return Task.FromResult(RestoreWarning); }
    }

    private sealed class FakeAddressChanges : IAddressChangeSource, IDisposable
    {
        public event Action? Changed;
        public bool Disposed { get; private set; }
        public int Subscribers => Changed?.GetInvocationList().Length ?? 0;
        public void Raise() => Changed?.Invoke();
        public void Dispose() => Disposed = true;
    }

    private sealed class FakeReaper(List<string> order) : IConnectionReaper
    {
        public List<ReapPolicy> Policies { get; } = [];
        public ReapReport Result { get; set; } = new(0, 0, 0);
        public Exception? Error { get; set; }
        public ReapReport Reap(ReapPolicy policy)
        { order.Add("reap"); Policies.Add(policy); if (Error is not null) throw Error; return Result; }
    }

    private static ClientController NicController(List<string> order, FakeNic? nic, FakeReaper? reaper, Timers? timers = null,
        Firewall? firewall = null, MemoryRouting? routing = null, SessionResponse? session = null, FakeAddressChanges? changes = null)
    {
        timers ??= new Timers();
        var source = new ScriptedSource(); source.Enqueue(Ok(session ?? TestData.Session()));
        var controller = new ClientController(source, firewall ?? new Firewall(order), new Tunnel(order), Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, routingSettings: routing, serviceProcessPath: RoutingTests.Service, nicGuard: nic, reaper: reaper,
            addressChanges: changes)
            { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        return controller;
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public async Task ConnectRefusedWhenAdapterHasPublicIpv4(bool apps, bool fromUser)
    {
        var order = new List<string>();
        var nic = new FakeNic(order) { PublicIpv4 = "拨号连接" };
        using var controller = NicController(order, nic, new FakeReaper(order),
            routing: new MemoryRouting { Policy = apps ? RoutingTests.Apps : RoutingPolicy.Global },
            session: apps ? AppsSession() : null);
        await controller.ConnectAsync(fromUser);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.Equal("网卡「拨号连接」上直接有公网 IPv4 地址(通常是电脑自己拨号上网),部分软件和网页可以直接读到这个地址,已拒绝连接。请改由路由器拨号上网后再连接,或联系管理员。",
            controller.Snapshot.Message);
        Assert.Equal(new[] { "nic-check" }, order);
        nic.PublicIpv4 = null;
        nic.PublicIpv4Error = new InvalidOperationException("无法读取网卡地址");
        await controller.ConnectAsync(fromUser);
        Assert.Equal("无法读取网卡地址,已拒绝连接;请重试或联系管理员。", controller.Snapshot.Message);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.DoesNotContain("apply", order);
    }

    [Fact]
    public async Task NicGuardAppliedAfterFirewallBeforeTunnel()
    {
        var order = new List<string>();
        using var controller = NicController(order, new FakeNic(order), new FakeReaper(order));
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(new[] { "nic-check", "apply", "nic-apply", "reap", "start" }, order);
        Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
    }

    [Fact]
    public async Task HeldProtectionKeepsTunnelWhenNicGuardFails()
    {
        var order = new List<string>();
        var nic = new FakeNic(order) { ApplyError = new NicGuardException("未能关闭网卡「以太网」的 IPv6,其公网 IPv6 地址可能被网页读到,已拒绝连接。") { AdapterName = "以太网" } };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order) { HasPendingState = true }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            nicGuard: nic, reaper: new FakeReaper(order));
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("start", order);
        Assert.DoesNotContain("nic-restore", order);
        Assert.Equal("未能关闭网卡「以太网」的 IPv6,隧道保持,但该网卡的公网 IPv6 地址可能被网页读到;请联系管理员。", controller.Snapshot.Message);
        Assert.Equal(controller.Snapshot.Message, controller.Snapshot.GuardStatus);
    }

    [Fact]
    public async Task NicGuardFailureOnFirstConnectRestoresNetworkAndNic()
    {
        var order = new List<string>();
        var nic = new FakeNic(order) { ApplyError = new NicGuardException("拒绝文案") { AdapterName = "以太网" } };
        using var controller = NicController(order, nic, new FakeReaper(order));
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Equal("连接失败，已恢复原来的网络，当前没有走澳洲出口。原因：没能关闭网卡「以太网」的 IPv6。", controller.Snapshot.Message);
        Assert.DoesNotContain("start", order);
        Assert.DoesNotContain("reap", order);
        Assert.True(order.IndexOf("nic-restore") > order.IndexOf("remove"));
    }

    [Fact]
    public async Task DisconnectRestoresNicAfterFirewall()
    {
        var order = new List<string>();
        var nic = new FakeNic(order) { RestoreWarning = "网卡「以太网」的 IPv6 未能恢复,请重试断开或联系管理员。" };
        using var controller = NicController(order, nic, new FakeReaper(order));
        await controller.ConnectAsync();
        order.Clear();
        await controller.DisconnectAsync();
        Assert.Equal(new[] { "stop", "remove", "nic-restore" }, order);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.StartsWith("已断开", controller.Snapshot.Message);
        Assert.EndsWith(" 网卡「以太网」的 IPv6 未能恢复,请重试断开或联系管理员。", controller.Snapshot.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StartupRestoresNicOnlyWithoutKeepProtection(bool keep)
    {
        var order = new List<string>();
        var nic = new FakeNic(order) { RestoreWarning = "网卡「以太网」的 IPv6 未能恢复,请重试断开或联系管理员。" };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            new Firewall(order) { HasPendingState = keep }, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            nicGuard: nic, reaper: new FakeReaper(order));
        await controller.InitializeAsync(autoConnect: false, keepProtection: keep);
        if (keep) Assert.DoesNotContain("nic-restore", order);
        else
        {
            Assert.Equal(new[] { "recover", "nic-restore" }, order);
            Assert.Contains("网卡「以太网」的 IPv6 未能恢复", controller.Snapshot.Message);
        }
    }

    [Fact]
    public async Task PatrolDisablesNewIpv6AdapterAndReportsNicFailure()
    {
        var order = new List<string>();
        var timers = new Timers();
        var nic = new FakeNic(order) { PatrolResult = new(["以太网"], []) };
        using var controller = NicController(order, nic, new FakeReaper(order), timers);
        await controller.ConnectAsync();
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Equal("正常,已关闭新出现公网 IPv6 的网卡 1 个", controller.Snapshot.GuardStatus);
        nic.PatrolError = new NicGuardException("巡检失败文案");
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Equal("巡检失败文案", controller.Snapshot.Message);
        Assert.Equal("巡检失败文案", controller.Snapshot.GuardStatus);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.DoesNotContain("remove", order);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicIpv4MidSessionStopsTunnelAndKeepsProtection(bool apps)
    {
        var order = new List<string>();
        var timers = new Timers();
        var nic = new FakeNic(order);
        using var controller = NicController(order, nic, new FakeReaper(order), timers,
            routing: new MemoryRouting { Policy = apps ? RoutingTests.Apps : RoutingPolicy.Global },
            session: apps ? AppsSession() : null);
        await controller.ConnectAsync();
        nic.PatrolResult = new([], ["拨号连接"]);
        await FireParkedPatrol(controller, timers);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Contains("stop", order);
        Assert.DoesNotContain("remove", order);
        Assert.Equal(ClientController.PublicIpv4ParkedMessage("拨号连接", apps), controller.Snapshot.Message);
        Assert.Equal(ClientController.PublicIpv4GuardStatus("拨号连接"), controller.Snapshot.GuardStatus);
        await FireParkedPatrol(controller, timers);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ClientController.PublicIpv4ParkedMessage("拨号连接", apps), controller.Snapshot.Message);
        Assert.Equal(1, order.Count(x => x == "stop"));
    }

    [Fact]
    public async Task ParkedPatrolReportsPublicIpv4InStatusOnly()
    {
        var order = new List<string>();
        var timers = new Timers();
        var nic = new FakeNic(order);
        var tunnel = new ObservableTunnel(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, new Firewall(order), tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay, nicGuard: nic, reaper: new FakeReaper(order)) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        tunnel.FailStop = true;
        source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.InvalidToken));
        await controller.RefreshSessionAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        var parked = controller.Snapshot.Message;
        nic.PatrolResult = new([], ["拨号连接"]);
        await FireParkedPatrol(controller, timers);
        Assert.Equal(ClientController.PublicIpv4GuardStatus("拨号连接"), controller.Snapshot.GuardStatus);
        Assert.Equal(parked, controller.Snapshot.Message);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
    }

    [Fact]
    public async Task PublicIpv4DuringFirstAttemptRestoresNetwork()
    {
        var order = new List<string>();
        var timers = new Timers();
        var changes = new FakeAddressChanges();
        var nic = new FakeNic(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, new Firewall(order), new FirstStartBrokenTunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay, nicGuard: nic, reaper: new FakeReaper(order),
            addressChanges: changes) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Reconnecting, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        nic.PatrolResult = new([], ["拨号连接"]);
        changes.Raise();
        await FireNicSweep(controller, timers);
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Contains("remove", order);
        Assert.Equal("连接失败，已恢复原来的网络，当前没有走澳洲出口。原因：网卡「拨号连接」上出现了公网 IPv4 地址。",
            controller.Snapshot.Message);
    }

    [Fact]
    public async Task AddressChangeTightensNicWithinSeconds()
    {
        var order = new List<string>();
        var timers = new Timers();
        var changes = new FakeAddressChanges();
        var nic = new FakeNic(order) { PatrolResult = new(["以太网"], []) };
        using var controller = NicController(order, nic, new FakeReaper(order), timers, changes: changes);
        await controller.ConnectAsync();
        var before = order.Count(x => x == "nic-patrol");
        changes.Raise();
        changes.Raise();
        changes.Raise();
        Assert.Single(timers.For("网卡收紧"));
        Assert.Equal(ClientController.NicSweepDelay, Assert.Single(timers.For("网卡收紧")));
        await FireAndPublish(controller, timers, "网卡收紧", ClientController.NicSweepDelay);
        Assert.Equal(before + 1, order.Count(x => x == "nic-patrol"));
        Assert.Equal("已关闭新出现公网 IPv6 的网卡 1 个", controller.Snapshot.GuardStatus);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        changes.Raise();
        Assert.Equal(2, timers.For("网卡收紧").Length);
    }

    [Fact]
    public async Task AddressChangeParksOnPublicIpv4()
    {
        var order = new List<string>();
        var timers = new Timers();
        var changes = new FakeAddressChanges();
        var nic = new FakeNic(order);
        using var controller = NicController(order, nic, new FakeReaper(order), timers, changes: changes);
        await controller.ConnectAsync();
        nic.PatrolResult = new([], ["拨号连接"]);
        changes.Raise();
        await FireNicSweep(controller, timers);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(ClientController.PublicIpv4ParkedMessage("拨号连接", false), controller.Snapshot.Message);
        Assert.True(controller.Snapshot.ProtectionActive);
    }

    [Fact]
    public async Task AddressChangeIgnoredWithoutProtection()
    {
        var order = new List<string>();
        var timers = new Timers();
        var changes = new FakeAddressChanges();
        using var controller = NicController(order, new FakeNic(order), new FakeReaper(order), timers, changes: changes);
        changes.Raise();
        Assert.Empty(timers.For("网卡收紧"));
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        var before = timers.For("网卡收紧").Length;
        changes.Raise();
        Assert.Equal(before, timers.For("网卡收紧").Length);
    }

    [Fact]
    public async Task DisposeUnsubscribesAddressChanges()
    {
        var order = new List<string>();
        var changes = new FakeAddressChanges();
        var controller = NicController(order, new FakeNic(order), new FakeReaper(order), changes: changes);
        Assert.Equal(1, changes.Subscribers);
        controller.Dispose();
        Assert.Equal(0, changes.Subscribers);
        Assert.True(changes.Disposed);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task HeldFirewallFailureStillTightensNic()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true,
            ApplyError = new WfpUnavailableException(KillSwitchApplier.WfpConnectRefused) };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            nicGuard: new FakeNic(order), reaper: new FakeReaper(order));
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.True(order.IndexOf("nic-apply") > order.IndexOf("apply"));
        Assert.True(order.IndexOf("nic-apply") < order.IndexOf("start"));
        Assert.DoesNotContain("reap", order);
        Assert.Equal("断网保护未能重新套用:系统过滤层的过滤器未能建立,隧道保持,但缺少这道断网兜底;请联系管理员", controller.Snapshot.Message);
    }

    [Fact]
    public async Task HeldFirewallAndNicFailuresBothReported()
    {
        var order = new List<string>();
        var firewall = new Firewall(order) { HasPendingState = true,
            ApplyError = new WfpUnavailableException(KillSwitchApplier.WfpConnectRefused) };
        var nic = new FakeNic(order) { ApplyError = new NicGuardException("拒绝文案") { AdapterName = "以太网" } };
        using var controller = new ClientController(new PairingSessionSource(PairingTests.ValidPairing()),
            firewall, new Tunnel(order), Path.GetFullPath("fake.exe"), TestData.Device,
            nicGuard: nic, reaper: new FakeReaper(order));
        await controller.InitializeAsync(autoConnect: false, keepProtection: true);
        const string fw = "断网保护未能重新套用:系统过滤层的过滤器未能建立,隧道保持,但缺少这道断网兜底;请联系管理员";
        const string nicText = "未能关闭网卡「以太网」的 IPv6,隧道保持,但该网卡的公网 IPv6 地址可能被网页读到;请联系管理员。";
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(fw + " " + nicText, controller.Snapshot.Message);
        Assert.Equal(controller.Snapshot.Message, controller.Snapshot.GuardStatus);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StaleConnectionsReapedAfterKillSwitch(bool apps)
    {
        var order = new List<string>();
        var reaper = new FakeReaper(order) { Result = new(5, 1, 3) };
        using var controller = NicController(order, new FakeNic(order), reaper,
            routing: new MemoryRouting { Policy = apps ? RoutingTests.Apps : RoutingPolicy.Global }, session: apps ? AppsSession() : null);
        await controller.ConnectAsync();
        var policy = Assert.Single(reaper.Policies);
        Assert.Equal(apps, policy.AppsMode);
        Assert.Equal(apps ? RoutingTests.Apps.Apps.ToArray() : Array.Empty<string>(), policy.Apps.ToArray());
        Assert.Equal(Path.GetFullPath("fake.exe"), policy.KernelPath);
        Assert.Equal(new[] { IPAddress.Parse("192.0.2.5") }, policy.NodeIps);
        Assert.Null(policy.Auth);
        Assert.True(order.IndexOf("reap") > order.IndexOf("apply" + (apps ? "-apps" : "")));
        Assert.True(order.IndexOf("reap") < order.IndexOf("start"));
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal("虚拟网卡已就绪。 有 3 条连接前建立的连接未能重置,相关软件可能仍走原网络,请重启这些软件。", controller.Snapshot.Message);
    }

    [Fact]
    public async Task ReaperFailureNeverBlocksConnection()
    {
        var order = new List<string>();
        var reaper = new FakeReaper(order) { Error = new System.ComponentModel.Win32Exception(5) };
        using var controller = NicController(order, new FakeNic(order), reaper);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Contains("start", order);
        Assert.Equal("虚拟网卡已就绪。", controller.Snapshot.Message);
    }

    [Theory]
    [InlineData("rejection", ConnectionState.NeedsLogin)]
    [InlineData("failure", ConnectionState.NeedsManual)]
    public async Task PatrolContinuesWhileParkedWithProtection(string reason, ConnectionState expected)
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var tunnel = new ObservableTunnel(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, firewall, tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.InvalidToken));
        tunnel.FailStop = reason == "failure";
        await controller.RefreshSessionAsync();
        Assert.Equal(expected, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        var parked = controller.Snapshot.Message;
        await FireParkedPatrol(controller, timers);
        Assert.Single(firewall.PatrolCalls);
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
        Assert.Equal(expected, controller.Snapshot.State);
        Assert.Equal(parked, controller.Snapshot.Message);
        Assert.DoesNotContain("remove", order);
        await FireParkedPatrol(controller, timers);
        Assert.Equal(2, firewall.PatrolCalls.Count);
    }

    [Fact]
    public async Task PatrolRearmsAfterFailedDisconnect()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var tunnel = new ObservableTunnel(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, firewall, tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        tunnel.FailStop = true;
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        Assert.Equal(2, timers.For("巡检").Length);
        var parked = controller.Snapshot.Message;
        firewall.PatrolResults.Enqueue(new PatrolReport([], [], ["YuanC-KS-Tun"]));
        await FireParkedPatrol(controller, timers);
        Assert.Equal("已重建 1 条本项目规则", controller.Snapshot.GuardStatus);
        Assert.Equal(2, order.Count(x => x == "apply"));
        Assert.Equal(parked, controller.Snapshot.Message);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal(3, timers.For("巡检").Length);
    }

    [Fact]
    public async Task ParkedPatrolWarningStaysOutOfMessage()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var tunnel = new ObservableTunnel(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, firewall, tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        tunnel.FailStop = true;
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        var parked = controller.Snapshot.Message;
        firewall.PatrolResults.Enqueue(new FirewallIneffectiveException("防火墙失效"));
        await FireParkedPatrol(controller, timers);
        Assert.Contains("防火墙", controller.Snapshot.GuardStatus);
        Assert.Equal(parked, controller.Snapshot.Message);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
    }

    [Fact]
    public async Task StartupParkedWithoutSourceStillPatrols()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { HasPendingState = true };
        using var controller = new ClientController((ISessionSource?)null, firewall, new Tunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.InitializeAsync(true, true);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Single(timers.For("巡检"));
        await FireParkedPatrol(controller, timers);
        Assert.Single(firewall.PatrolCalls);
        Assert.True(Assert.Single(firewall.EnforceDefaultCalls));
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
        Assert.Equal(ClientController.KeptWithoutPairingMessage, controller.Snapshot.Message);
        firewall.PatrolResults.Enqueue(new PatrolReport([], [], ["YuanC-KS-Tun"]));
        await FireParkedPatrol(controller, timers);
        Assert.Equal("巡检失败,下一轮重试", controller.Snapshot.GuardStatus);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("recover", order);
        Assert.DoesNotContain("remove", order);
        Assert.Equal(ClientController.KeptWithoutPairingMessage, controller.Snapshot.Message);
    }

    [Fact]
    public async Task StartupParkedAppsModePatrolsAppRules()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { HasPendingState = true, PendingMode = "apps" };
        var files = new List<string> { ScopeDir + @"\Update.exe" };
        using var controller = new ClientController((ISessionSource?)null, firewall, new Tunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay,
            routingSettings: new MemoryRouting { Policy = RoutingPolicy.Create("apps", [ScopeSelected]) },
            scopeResolver: ScopeOf(files)) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.InitializeAsync(true, true);
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.Equal("apps", controller.Snapshot.RoutingMode);
        await FireParkedPatrol(controller, timers);
        Assert.Equal(KillSwitchPlanner.AppRuleNames(1), Assert.Single(firewall.PatrolCalls));
        Assert.False(Assert.Single(firewall.EnforceDefaultCalls));
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
        Assert.Empty(firewall.AppliedFilters);
        files.Add(ScopeDir + @"\helper.exe");
        await FireParkedPatrol(controller, timers);
        Assert.Single(firewall.AppliedFilters);
        Assert.Equal("已为新出现的 1 个程序文件补上保护", controller.Snapshot.GuardStatus);
        Assert.Equal(ClientController.KeptWithoutPairingMessage, controller.Snapshot.Message);
    }

    [Fact]
    public async Task ParkedPatrolSkipsFirewallWhenRecordModeDiffers()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order) { HasPendingState = true, PendingMode = "apps" };
        using var controller = new ClientController((ISessionSource?)null, firewall, new Tunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.InitializeAsync(true, true);
        await FireParkedPatrol(controller, timers);
        Assert.Empty(firewall.PatrolCalls);
        Assert.Empty(firewall.EnforceDefaultCalls);
        Assert.Equal(ClientController.PatrolModeMismatchStatus, controller.Snapshot.GuardStatus);
        Assert.Equal(ClientController.KeptWithoutPairingMessage, controller.Snapshot.Message);
        Assert.Equal(2, timers.For("巡检").Length);
        Assert.DoesNotContain("apply", order);
        Assert.DoesNotContain("apply-apps", order);
    }

    [Fact]
    public async Task PatrolStopsOnceProtectionRemoved()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var tunnel = new ObservableTunnel(order);
        var source = new ScriptedSource(); source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, firewall, tunnel, Path.GetFullPath("fake.exe"),
            TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        source.Enqueue(new AuthResponse<SessionResponse>(AuthResult.InvalidToken));
        tunnel.FailStop = true;
        await controller.RefreshSessionAsync();
        Assert.Equal(ConnectionState.NeedsManual, controller.Snapshot.State);
        Assert.True(controller.Snapshot.ProtectionActive);
        tunnel.FailStop = false;
        await controller.DisconnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        var count = timers.For("巡检").Length;
        timers.Advance(TimeSpan.FromMinutes(10));
        await controller.RefreshSessionAsync();
        Assert.Empty(firewall.PatrolCalls);
        Assert.Equal(count, timers.For("巡检").Length);
        source.Enqueue(Ok(TestData.Session()));
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        Assert.Equal(count + 1, timers.For("巡检").Length);
    }

    [Fact]
    public async Task AbandonedFirstAttemptLeavesPatrolReadyForNextConnect()
    {
        var order = new List<string>();
        var timers = new Timers();
        var firewall = new Firewall(order);
        var source = new ScriptedSource();
        source.Enqueue(Ok(TestData.Session()));
        source.Enqueue(Ok(TestData.Session()));
        using var controller = new ClientController(source, firewall, new FirstStartMissingTunnel(order),
            Path.GetFullPath("fake.exe"), TestData.Device, timers.Delay) { DelayWithPurposeAsync = timers.Delay };
        controller.Changed += _ => Interlocked.Increment(ref timers.Published);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Disconnected, controller.Snapshot.State);
        Assert.False(controller.Snapshot.ProtectionActive);
        Assert.Contains("remove", order);
        await controller.ConnectAsync();
        Assert.Equal(ConnectionState.Connected, controller.Snapshot.State);
        await FireAndPublish(controller, timers, "巡检", TimeSpan.FromSeconds(60));
        Assert.Single(firewall.PatrolCalls);
        Assert.Equal("正常", controller.Snapshot.GuardStatus);
    }

    private sealed class Firewall(List<string> order) : IKillSwitch
    {
        public bool BlockPatrol { get; set; }
        public TaskCompletionSource PatrolStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken PatrolToken { get; private set; }
        public async Task<PatrolReport> PatrolAsync(IReadOnlyList<string> rules, bool enforceDefaultBlock, CancellationToken token)
        {
            if (!BlockPatrol) return await PatrolAsync(rules, enforceDefaultBlock);
            PatrolToken = token;
            PatrolStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new InvalidOperationException("巡检应只在取消时结束。");
        }
        public string? PendingMode { get; set; }
        public string[] AppliedApps { get; private set; } = [];
        public List<bool> EnforceDefaultCalls { get; } = [];
        public Exception? ApplyAppsError { get; set; }
        public List<string[]> AppliedFilters { get; } = [];
        public Task ApplyAppsAsync(IReadOnlyList<string> programs, IReadOnlyList<string> filterPrograms)
        { AppliedFilters.Add(filterPrograms.ToArray()); return ApplyAppsAsync(programs); }
        public Task ApplyAppsAsync(IReadOnlyList<string> programs)
        { AppliedApps = programs.ToArray(); order.Add("apply-apps"); if (ApplyAppsError is not null) throw ApplyAppsError; return Task.CompletedTask; }
        public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> rules, bool enforceDefaultBlock)
        { EnforceDefaultCalls.Add(enforceDefaultBlock); return PatrolAsync(rules); }
        public List<string[]> PatrolCalls { get; } = [];
        public Queue<object> PatrolResults { get; } = new();
        public Exception? ReapplyError { get; set; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, int realityPort, AuthEndpoint? auth = null)
        {
            if (realityPort != 443) throw new InvalidOperationException("当前断网保护不支持此出口端口。");
            var applied = ApplyAsync(ips, program, hy2Port, auth);
            if (order.Count(x => x == "apply") > 1 && ReapplyError is not null) throw ReapplyError;
            return applied;
        }
        public Task<PatrolReport> PatrolAsync(IReadOnlyList<string> expectedRules)
        {
            PatrolCalls.Add(expectedRules.ToArray());
            var next = PatrolResults.Count == 0 ? PatrolReport.Empty : PatrolResults.Dequeue();
            if (next is Exception error) throw error;
            return Task.FromResult((PatrolReport)next);
        }
        public bool HasPendingState { get; set; }
        public string? LastRemoveWarning { get; set; }
        public AuthEndpoint? AppliedAuth { get; private set; }
        public string? RecoveryWarning { get; init; }
        public bool FailRecovery { get; init; }
        public bool FailApply { get; init; }
        public Exception? ApplyError { get; set; }
        public Task ApplyAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port, AuthEndpoint? auth = null)
        { AppliedAuth = auth; order.Add("apply"); if (ApplyError is not null) throw ApplyError; if (FailApply) throw new InvalidOperationException(); return Task.CompletedTask; }
        public Task UpdateNodeAsync(IReadOnlyList<IPAddress> ips, string program, int hy2Port)
        { order.Add("update:" + ips[0]); return Task.CompletedTask; }
        public Task RemoveAsync() { order.Add("remove"); return Task.CompletedTask; }
        public Task<string?> RecoverAsync()
        { order.Add("recover"); if (FailRecovery) throw new InvalidOperationException(); return Task.FromResult(RecoveryWarning); }
    }
    private sealed class Tunnel(List<string> order) : ITunnelTransport
    {
        public JsonElement Config { get; private set; }
        public event EventHandler? TunnelDown { add { } remove { } }
        public Task StartAsync(JsonElement configuration, CancellationToken cancellationToken) { Config = configuration; order.Add("start"); return Task.CompletedTask; }
        public void Stop() => order.Add("stop");
        public void Dispose() { }
    }
}
