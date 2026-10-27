using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Text.Json;
using WinClient.Core.Client;
using WinClient.Core.Firewall;
using WinClient.Core.Pairing;
using Xunit;

namespace WinClient.Tests;

public sealed class RouteLiveFactAttribute : FactAttribute
{
    public RouteLiveFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("YUANC_ROUTE_LIVE") != "1" || !OperatingSystem.IsWindows())
        { Skip = "真机路由测试需显式开启并以管理员运行。"; return; }
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            Skip = "真机路由测试需要管理员权限。";
    }
}

[CollectionDefinition("Route live serial", DisableParallelization = true)]
public sealed class RouteLiveCollection;

[Collection("Route live serial")]
public sealed class RouteGuardTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.1")];
    private static string ProgramPath => Path.Combine(Path.GetTempPath(), "route-test-kernel.exe");

    [Fact]
    public async Task InstallScriptAddsBothPrefixesToBothStores()
    {
        var runner = new Runner();
        await new RouteGuard(runner).InstallAsync(default);
        foreach (var value in new[] { "0.0.0.0/1", "128.0.0.0/1", "9473", "LoopbackInterfaceIndex", "ActiveStore", "PersistentStore", "New-NetRoute" })
            Assert.Contains(value, runner.Script);
        Assert.True(runner.Start!.CreateNoWindow);
        Assert.False(runner.Start.UseShellExecute);
        Assert.True(runner.Token.CanBeCanceled);
    }

    [Fact]
    public async Task RemoveScriptOnlyTouchesOwnRoutes()
    {
        var runner = new Runner();
        await new RouteGuard(runner).RemoveAsync(default);
        Assert.Contains("DestinationPrefix", runner.Script);
        Assert.Contains("InterfaceIndex -eq $lo", runner.Script);
        Assert.Contains("RouteMetric -eq 9473", runner.Script);
        Assert.Contains("$prefixes -contains", runner.Script);
        Assert.Contains("Remove-NetRoute", runner.Script);
        Assert.Contains("ActiveStore", runner.Script);
        Assert.Contains("PersistentStore", runner.Script);
    }

    [Fact]
    public async Task NonZeroExitThrowsRouteGuardException()
    {
        var guard = new RouteGuard(new Runner { ExitCode = 1 });
        await Assert.ThrowsAsync<RouteGuardException>(() => guard.InstallAsync(default));
        await Assert.ThrowsAsync<RouteGuardException>(() => guard.RemoveAsync(default));
        await Assert.ThrowsAsync<RouteGuardException>(() => guard.IsInstalledAsync(default));
    }

    [Fact]
    public async Task GlobalApplyInstallsRoutes()
    {
        using var f = new Fixture();
        await f.Apply();
        Assert.Equal(new[] { "firewall", "install" }, f.Order);
    }

    [Fact]
    public async Task ApplyFailsWhenRoutesCannotInstall()
    {
        using var f = new Fixture(); f.Routes.FailInstall = true;
        var error = await Assert.ThrowsAsync<RouteGuardUnavailableException>(f.Apply);
        Assert.Equal(KillSwitchApplier.RouteConnectRefused, error.Message);
    }

    [Fact]
    public async Task AppsModeDoesNotInstallRoutes()
    {
        using var f = new Fixture();
        await f.Applier.ApplyAppsAsync([ProgramPath]);
        Assert.Equal(new[] { "firewall" }, f.Order);
    }

    [Fact]
    public async Task RemoveAlwaysRemovesRoutes()
    {
        using var f = new Fixture();
        await f.Applier.RemoveAsync();
        Assert.Equal(new[] { "firewall", "remove" }, f.Order);
    }

    [Fact]
    public async Task RemoveStillRemovesRoutesWhenFirewallFails()
    {
        using var f = new Fixture(); f.Runner.ExitCode = 1; f.Routes.FailRemove = true;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RemoveAsync());
        Assert.Equal("防火墙操作失败，恢复记录已保留，请联系管理员。", error.Message);
        Assert.Equal(new[] { "firewall", "remove" }, f.Order);
    }

    [Fact]
    public async Task RecoverRemovesRoutesWithoutState()
    {
        using var f = new Fixture();
        Assert.False(f.Applier.HasPendingState);
        await f.Applier.RecoverAsync();
        Assert.Equal(new[] { "remove" }, f.Order);
    }

    [Fact]
    public async Task RouteOffSkipsInstall()
    {
        using var f = new Fixture(); f.Routes.FailRemove = true;
        File.WriteAllText(Path.Combine(f.Directory.Path, "route-off"), "");
        await f.Apply();
        Assert.Equal(new[] { "firewall", "remove" }, f.Order);
        f.Order.Clear(); await f.Applier.PatrolAsync([]);
        Assert.Equal(new[] { "firewall" }, f.Order);
    }

    [Fact]
    public async Task PatrolRebuildsMissingRoutes()
    {
        using var f = new Fixture(); await f.Apply();
        f.Order.Clear(); f.Routes.Installed = false;
        f.Runner.Output = "{\"reenforced\":[],\"newly_disabled\":[],\"missing_rules\":[\"原规则\"]}";
        var report = await f.Applier.PatrolAsync([]);
        Assert.Equal(new[] { "原规则", RouteGuard.MissingMarker }, report.MissingRules);
        Assert.Equal(new[] { "firewall", "query", "install" }, f.Order);
    }

    [Fact]
    public async Task PatrolThrowsWhenRebuildFails()
    {
        using var f = new Fixture(); await f.Apply();
        f.Routes.Installed = false; f.Routes.FailInstall = true;
        var error = await Assert.ThrowsAsync<RouteGuardUnavailableException>(() => f.Applier.PatrolAsync([]));
        Assert.Equal(KillSwitchApplier.RoutePatrolFailed, error.Message);
    }

    [Fact]
    public async Task PatrolSkipsRoutesWhenNotApplied()
    {
        using var f = new Fixture();
        await f.Applier.PatrolAsync([]);
        Assert.Equal(new[] { "firewall" }, f.Order);
    }

    [Fact]
    public void LocalConfigTunUsesQuarterRoutes()
    {
        var config = LocalConfigRenderer.Render(PairingTests.ValidPairing().Node);
        Assert.False(config.GetProperty("inbounds")[0].TryGetProperty("route_address", out _));
        var rendered = TunnelTransport.RenderConfiguration(config);
        Assert.Equal(RouteGuard.TunRoutes, rendered.GetProperty("inbounds")[0].GetProperty("route_address")
            .EnumerateArray().Select(v => v.GetString()).ToArray());
    }

    [Fact]
    public void ServerConfigTunRoutesOverridden()
    {
        var config = JsonSerializer.SerializeToElement(new { inbounds = new[] { new { type = "tun", route_address = new[] { "0.0.0.0/0" } } } });
        var rendered = TunnelTransport.RenderConfiguration(config);
        Assert.Equal(RouteGuard.TunRoutes, rendered.GetProperty("inbounds")[0].GetProperty("route_address")
            .EnumerateArray().Select(v => v.GetString()).ToArray());
        Assert.Equal("0.0.0.0/0", config.GetProperty("inbounds")[0].GetProperty("route_address")[0].GetString());
    }

    [Fact]
    public async Task GlobalExplicitPortInstallsRoutesButNodeUpdateDoesNot()
    {
        using var f = new Fixture();
        await f.Applier.ApplyAsync(Ips, ProgramPath, 444, 8443);
        Assert.Equal(new[] { "firewall", "install" }, f.Order);
        f.Order.Clear();
        await f.Applier.UpdateNodeAsync(Ips, ProgramPath, 444, 8443);
        Assert.Equal(new[] { "firewall" }, f.Order);
    }

    [Fact]
    public async Task RouteRemovalFailureIsReportedAndSuccessfulRemovalClearsPatrolMarker()
    {
        using var f = new Fixture(); await f.Apply();
        f.Routes.FailRemove = true;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RemoveAsync());
        Assert.Equal(KillSwitchApplier.RouteRemoveFailed, error.Message);
        f.Routes.FailRemove = false; await f.Applier.RemoveAsync();
        f.Order.Clear(); await f.Applier.PatrolAsync([]);
        Assert.Equal(new[] { "firewall" }, f.Order);
    }

    [Fact]
    public async Task RecoverRemovesRoutesAfterFirewallFailureAndKeepsOriginalError()
    {
        using var f = new Fixture();
        File.WriteAllText(f.Applier.StatePath, "{}");
        f.Runner.ExitCode = 1; f.Routes.FailRemove = true;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RecoverAsync());
        Assert.Equal("防火墙操作失败，恢复记录已保留，请联系管理员。", error.Message);
        Assert.Equal("remove", f.Order.Last());
        Assert.Equal(1, f.Order.Count(value => value == "remove"));
    }

    [Fact]
    public async Task RecoverReportsOnlyRouteFailureWithoutState()
    {
        using var f = new Fixture(); f.Routes.FailRemove = true;
        Assert.Equal(KillSwitchApplier.RouteRemoveFailed,
            (await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RecoverAsync())).Message);
        Assert.Equal(new[] { "remove" }, f.Order);
    }

    [Fact]
    public async Task InstalledRoutesAreNotRebuiltAndFirewallPatrolFailureHasPriority()
    {
        using var f = new Fixture(); await f.Apply();
        f.Order.Clear();
        Assert.Empty((await f.Applier.PatrolAsync([])).MissingRules);
        Assert.Equal(new[] { "firewall", "query" }, f.Order);
        f.Runner.ExitCode = KillSwitchApplier.VerifyFailedExitCode;
        f.Routes.Installed = false; f.Routes.FailInstall = true;
        Assert.IsType<FirewallIneffectiveException>(await Record.ExceptionAsync(() => f.Applier.PatrolAsync([])));
    }

    [Theory]
    [InlineData("1\r\n", true)]
    [InlineData("0\r\n", false)]
    public async Task QueryReadsPresenceAndOnlyUsesActiveStore(string output, bool installed)
    {
        var runner = new Runner { Output = output };
        Assert.Equal(installed, await new RouteGuard(runner).IsInstalledAsync(default));
        Assert.Contains("ActiveStore", runner.Script);
        Assert.DoesNotContain("PersistentStore", runner.Script);
    }

    [Fact]
    public async Task RunnerFailureDoesNotExposeOriginalError()
    {
        var runner = new FailedRunner();
        var error = await Assert.ThrowsAsync<RouteGuardException>(() => new RouteGuard(runner).InstallAsync(default));
        Assert.DoesNotContain("测试原始信息", error.ToString());
        Assert.Null(error.InnerException);
    }

    private sealed class FailedRunner : ICommandRunner
    {
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default) =>
            throw new OperationCanceledException("测试原始信息");
    }

    [RouteLiveFact]
    public async Task LiveInstallAndRemoveLeaveDecoy()
    {
        string[] prefixes = ["203.0.113.0/25", "203.0.113.128/25"];
        var guard = new RouteGuard(null, prefixes);
        var runner = new CommandRunner();
        var ownsDecoy = false;
        const string setup = """
            $ErrorActionPreference = 'Stop'
            $lo = [System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex
            $prefixes = @('203.0.113.0/25','203.0.113.128/25')
            """;
        async Task Run(string body)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var result = await runner.RunAsync(KillSwitchApplier.CreateStartInfo(setup + "\n" + body), timeout.Token);
            Assert.True(result.ExitCode == 0, "真机路由操作或核验失败。");
        }
        try
        {
            await Run("""
                if (@(Get-NetRoute -ErrorAction Stop | Where-Object {
                    $prefixes -contains $_.DestinationPrefix -and $_.InterfaceIndex -eq $lo -and
                    ($_.RouteMetric -eq 9472 -or $_.RouteMetric -eq 9473) }).Count) { exit 1 }
                New-NetRoute -DestinationPrefix '203.0.113.0/24' -InterfaceIndex $lo -NextHop 0.0.0.0 -RouteMetric 9472 -PolicyStore ActiveStore | Out-Null
                exit 0
                """);
            ownsDecoy = true;
            await guard.InstallAsync(default);
            await guard.InstallAsync(default);
            await Run("""
                foreach ($store in @('ActiveStore','PersistentStore')) {
                    foreach ($p in $prefixes) {
                        $found = @(Get-NetRoute -PolicyStore $store | Where-Object {
                            $_.DestinationPrefix -eq $p -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq 9473 })
                        if ($found.Count -ne 1) { exit 1 }
                    }
                }
                exit 0
                """);
            Assert.True(await guard.IsInstalledAsync(default));
            await guard.RemoveAsync(default);
            await Run("""
                foreach ($store in @('ActiveStore','PersistentStore')) {
                    if (@(Get-NetRoute -PolicyStore $store | Where-Object {
                        $prefixes -contains $_.DestinationPrefix -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq 9473 }).Count) { exit 1 }
                }
                if (@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
                    $_.DestinationPrefix -eq '203.0.113.0/24' -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq 9472 }).Count -ne 1) { exit 1 }
                exit 0
                """);
            Assert.False(await guard.IsInstalledAsync(default));
        }
        finally
        {
            if (ownsDecoy)
            {
                try { await guard.RemoveAsync(default); }
                finally { await Run("""
                Get-NetRoute -PolicyStore ActiveStore | Where-Object {
                    $_.DestinationPrefix -eq '203.0.113.0/24' -and $_.InterfaceIndex -eq $lo -and $_.RouteMetric -eq 9472
                } | Remove-NetRoute -Confirm:$false | Out-Null
                exit 0
                """); }
            }
        }
    }

    private sealed class Fixture : IDisposable
    {
        public TempDirectory Directory { get; } = new();
        public List<string> Order { get; } = [];
        public Runner Runner { get; }
        public Routes Routes { get; }
        public KillSwitchApplier Applier { get; }
        public Fixture()
        {
            Runner = new(Order); Routes = new(Order);
            Applier = new(Directory.Path, Runner, routes: Routes);
        }
        public Task Apply() => Applier.ApplyAsync(Ips, ProgramPath, 443);
        public void Dispose() => Directory.Dispose();
    }

    private sealed class Runner(List<string>? order = null) : ICommandRunner
    {
        public int ExitCode;
        public string Output = "{\"reenforced\":[],\"newly_disabled\":[],\"missing_rules\":[]}";
        public string Script = "";
        public ProcessStartInfo? Start;
        public CancellationToken Token;
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            order?.Add("firewall"); Script = startInfo.ArgumentList.Last(); Start = startInfo; Token = cancellationToken;
            return Task.FromResult(new CommandResult(ExitCode, Output));
        }
    }

    private sealed class Routes(List<string> order) : IRouteGuard
    {
        public bool Installed, FailInstall, FailRemove;
        public Task InstallAsync(CancellationToken token)
        {
            order.Add("install"); if (FailInstall) throw new RouteGuardException("测试安装失败");
            Installed = true; return Task.CompletedTask;
        }
        public Task RemoveAsync(CancellationToken token)
        {
            order.Add("remove"); if (FailRemove) throw new RouteGuardException("测试撤销失败");
            Installed = false; return Task.CompletedTask;
        }
        public Task<bool> IsInstalledAsync(CancellationToken token)
        { order.Add("query"); return Task.FromResult(Installed); }
    }
}
