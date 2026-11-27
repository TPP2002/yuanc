using System.Diagnostics;
using System.Net;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class WfpApplierTests
{
    private static readonly IPAddress[] Ips = [IPAddress.Parse("192.0.2.1")];
    private static string ProgramPath => Path.GetFullPath("kernel.exe");
    private static WfpException Failure => new("test", unchecked((int)0x80320001));

    [Fact]
    public async Task InstallPrecedesScript()
    {
        using var f = new Fixture();
        await f.Applier.ApplyAsync(Ips, ProgramPath, 443);
        Assert.Equal(new[] { "install", "script" }, f.Order);
    }

    [Fact]
    public async Task FirewallVerificationFailureHasPriority()
    {
        using var f = new Fixture(); f.Runner.ExitCode = 3;
        var error = await Assert.ThrowsAsync<FirewallIneffectiveException>(() => f.Applier.ApplyAsync(Ips, ProgramPath, 443));
        Assert.IsNotType<WfpUnavailableException>(error);
        f.Engine.InstallError = Failure;
        Assert.IsType<FirewallIneffectiveException>(await Record.ExceptionAsync(() => f.Applier.ApplyAsync(Ips, ProgramPath, 443)));
    }

    [Fact]
    public async Task WfpFailureStillRunsScriptAndRefusesConnection()
    {
        using var f = new Fixture(); f.Engine.InstallError = Failure;
        var error = await Assert.ThrowsAsync<WfpUnavailableException>(() => f.Applier.ApplyAsync(Ips, ProgramPath, 443));
        Assert.Equal(KillSwitchApplier.WfpConnectRefused, error.Message);
        Assert.Equal(new[] { "install", "script" }, f.Order);
    }

    [Fact]
    public async Task FailedScriptStillRemovesWfpAndKeepsOriginalError()
    {
        using var f = new Fixture(); f.Runner.ExitCode = 1; f.Engine.RemoveError = Failure;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RemoveAsync());
        Assert.Equal("防火墙操作失败，恢复记录已保留，请联系管理员。", error.Message);
        Assert.Equal(new[] { "script", "remove" }, f.Order);
    }

    [Fact]
    public async Task RemoveFailureReportsPossibleRemainingBlock()
    {
        using var f = new Fixture(); f.Engine.RemoveError = Failure;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RemoveAsync());
        Assert.Equal(KillSwitchApplier.WfpRemoveFailed, error.Message);
    }

    [Fact]
    public async Task RecoveryWithoutSnapshotStillRemovesAndReportsFailure()
    {
        using var f = new Fixture();
        Assert.False(f.Applier.HasPendingState);
        await f.Applier.RecoverAsync();
        Assert.Equal(new[] { "remove" }, f.Order);
        f.Engine.RemoveError = Failure;
        Assert.Equal(KillSwitchApplier.WfpRemoveFailed,
            (await Assert.ThrowsAsync<InvalidOperationException>(() => f.Applier.RecoverAsync())).Message);
    }

    [Fact]
    public async Task NodeUpdatePreservesAuthAndAppsClearIt()
    {
        using var f = new Fixture();
        var auth = new AuthEndpoint(IPAddress.Parse("192.0.2.9"), 8443, Path.GetFullPath("service.exe"));
        await f.Applier.ApplyAsync(Ips, ProgramPath, 443, auth);
        await f.Applier.UpdateNodeAsync([IPAddress.Parse("192.0.2.2")], ProgramPath, 444, 8444);
        var rule = Assert.Single(f.Engine.Policy.Where(p => p.Name == "YuanC-WFP-Auth"));
        Assert.Equal(auth.Program, rule.AppPath);
        Assert.Equal(new[] { "192.0.2.9/32" }, rule.RemoteAddresses);
        Assert.Equal(8443, rule.RemotePort);
        await f.Applier.ApplyAppsAsync([ProgramPath]);
        await f.Applier.UpdateNodeAsync(Ips, ProgramPath, 443);
        Assert.DoesNotContain(f.Engine.Policy, p => p.Name == "YuanC-WFP-Auth");
    }

    [Fact]
    public async Task ApplyAppsUsesExactProgramsForFirewallAndScopeForFilters()
    {
        using var f = new Fixture();
        var selected = Path.GetFullPath("selected.exe");
        var extra = Enumerable.Range(1, 40).Select(i => Path.GetFullPath($"extra{i}.exe")).ToArray();
        await f.Applier.ApplyAppsAsync([selected], [selected, .. extra]);
        // 过滤层:41 个程序,每个 6 条。
        Assert.Equal(41 * 6, f.Engine.Policy.Count);
        Assert.Contains(f.Engine.Policy, p => p.AppPath == extra[^1]);
        // 防火墙规则:只按所选的一个程序(规则名 YuanC-KS-App-1,没有 -2)。
        Assert.Contains("YuanC-KS-App-1", f.Runner.Script);
        Assert.DoesNotContain("YuanC-KS-App-2", f.Runner.Script);
        Assert.DoesNotContain("extra1.exe", f.Runner.Script);
        // 只传一个参数时与旧行为一致:过滤层也按所选程序。
        using var g = new Fixture();
        await g.Applier.ApplyAppsAsync([selected]);
        Assert.Equal(6, g.Engine.Policy.Count);
    }

    [Fact]
    public async Task PatrolComparesNamesAndCountAndAppendsMarkerOnlyAfterRepair()
    {
        using var f = new Fixture();
        await f.Applier.ApplyAsync(Ips, ProgramPath, 443);
        f.Order.Clear(); f.Engine.Names = f.Engine.Policy.Select(p => p.Name).Reverse().ToArray();
        Assert.Empty((await f.Applier.PatrolAsync([])).MissingRules);
        Assert.Equal(new[] { "list", "script" }, f.Order);
        f.Order.Clear(); f.Engine.Names = [.. f.Engine.Names, f.Engine.Names[0]];
        f.Runner.Output = "{\"reenforced\":[],\"newly_disabled\":[],\"missing_rules\":[\"old\"]}";
        Assert.Equal(new[] { "old", WfpPlanner.MissingMarker }, (await f.Applier.PatrolAsync([])).MissingRules);
        Assert.Equal(new[] { "list", "install", "script" }, f.Order);
    }

    [Fact]
    public async Task PatrolFailureStillRunsScriptAndFirewallFailureTakesPriority()
    {
        using var f = new Fixture(); await f.Applier.ApplyAsync(Ips, ProgramPath, 443);
        f.Engine.ListError = Failure; f.Order.Clear();
        Assert.Equal(KillSwitchApplier.WfpPatrolFailed,
            (await Assert.ThrowsAsync<WfpUnavailableException>(() => f.Applier.PatrolAsync([]))).Message);
        Assert.Equal(new[] { "list", "script" }, f.Order);
        f.Runner.ExitCode = 3;
        Assert.IsType<FirewallIneffectiveException>(await Record.ExceptionAsync(() => f.Applier.PatrolAsync([])));
    }

    [Fact]
    public async Task OffSwitchRemovesWithoutInstallingAndSkipsPatrol()
    {
        using var f = new Fixture(); File.WriteAllText(Path.Combine(f.Directory.Path, "wfp-off"), "");
        f.Engine.RemoveError = Failure;
        await f.Applier.ApplyAsync(Ips, ProgramPath, 443);
        Assert.Equal(new[] { "remove", "script" }, f.Order);
        f.Order.Clear(); await f.Applier.PatrolAsync([]);
        Assert.Equal(new[] { "script" }, f.Order);
    }

    [Fact]
    public async Task NoEnginePreservesExactLegacyScripts()
    {
        using var dir = new TempDirectory(); var runner = new Runner([]);
        var applier = new KillSwitchApplier(dir.Path, runner);
        await applier.ApplyAsync(Ips, ProgramPath, 443);
        Assert.Equal(KillSwitchPlanner.ToPowerShellScript(KillSwitchPlanner.Plan(Ips, KillSwitchPlanner.TunAlias, ProgramPath, 443, KillSwitchMode.Apply), applier.StatePath, applier.AuditPath), runner.Script);
        await applier.RemoveAsync();
        Assert.Equal(KillSwitchPlanner.ToPowerShellScript([new RemoveRulesByPrefix(KillSwitchPlanner.Prefix), new RestoreProfileDefault()], applier.StatePath, applier.AuditPath), runner.Script);
    }

    [Fact]
    public async Task GlobalPolicyKeepsDnsBlockAcrossNodeUpdateAndAppsDropIt()
    {
        using var f = new Fixture();
        await f.Applier.ApplyAsync(Ips, ProgramPath, 443);
        Assert.Equal(2, f.Engine.Policy.Count(p => p.Name.Contains("Dns53")));
        await f.Applier.UpdateNodeAsync([IPAddress.Parse("192.0.2.2")], ProgramPath, 444, 8444);
        Assert.Equal(2, f.Engine.Policy.Count(p => p.Name.Contains("Dns53")));
        await f.Applier.ApplyAppsAsync([ProgramPath]);
        Assert.DoesNotContain(f.Engine.Policy, p => p.Name.Contains("Dns53"));
    }

    [Fact]
    public async Task InvalidPolicyDoesNotTouchEitherEngine()
    {
        using var f = new Fixture();
        await Assert.ThrowsAnyAsync<ArgumentException>(() => f.Applier.ApplyAsync([IPAddress.IPv6Loopback], ProgramPath, 443));
        Assert.Empty(f.Order);
    }

    private sealed class Fixture : IDisposable
    {
        public TempDirectory Directory { get; } = new();
        public List<string> Order { get; } = [];
        public Engine Engine { get; }
        public Runner Runner { get; }
        public KillSwitchApplier Applier { get; }
        public Fixture() { Engine = new(Order); Runner = new(Order); Applier = new(Directory.Path, Runner, Engine); }
        public void Dispose() => Directory.Dispose();
    }
    private sealed class Engine(List<string> order) : IWfpEngine
    {
        public WfpException? InstallError, RemoveError, ListError;
        public IReadOnlyList<WfpFilterSpec> Policy { get; private set; } = [];
        public IReadOnlyList<string> Names { get; set; } = [];
        public void Install(IReadOnlyList<WfpFilterSpec> filters) { order.Add("install"); if (InstallError is not null) throw InstallError; Policy = filters; Names = filters.Select(p => p.Name).ToArray(); }
        public void Remove() { order.Add("remove"); if (RemoveError is not null) throw RemoveError; Policy = []; Names = []; }
        public IReadOnlyList<string> ListFilterNames() { order.Add("list"); if (ListError is not null) throw ListError; return Names; }
    }
    private sealed class Runner(List<string> order) : ICommandRunner
    {
        public int ExitCode { get; set; }
        public string Output { get; set; } = "{\"reenforced\":[],\"newly_disabled\":[],\"missing_rules\":[]}";
        public string? Script { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        { order.Add("script"); Script = startInfo.ArgumentList.Last(); return Task.FromResult(new CommandResult(ExitCode, Output)); }
    }
}
