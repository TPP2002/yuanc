using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Principal;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class WfpLiveFactAttribute : FactAttribute
{
    public WfpLiveFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("YUANC_WFP_LIVE") != "1")
            Skip = "真机过滤层测试:设 YUANC_WFP_LIVE=1 并以管理员运行才执行";
    }
}

[CollectionDefinition("WFP live serial", DisableParallelization = true)]
public sealed class WfpLiveCollection;

[Collection("WFP live serial")]
[SupportedOSPlatform("windows")]
public sealed class WfpLiveTests
{
    // 本文件专属测试身份。生产对象绝不参与测试或清理。
    private static readonly Guid TestProviderKey = new("fe19d24e-6ba0-4b85-ae90-2bc0de30600c");
    private static readonly Guid TestSublayerKey = new("84fa614c-c2b5-45d7-8c0c-19fb4c6b4dc5");
    private const string Prefix = "YuanC-WFPTEST-";

    [WfpLiveFact]
    public Task BlockDeniesWithinThreeSecondsAndRemoveReleases() => WithCleanEngine(async engine =>
    {
        InstallGuarded(engine, [Rule("Block", "192.0.2.1/32")]);
        await AssertBlocked("192.0.2.1");
        engine.Remove();
        Assert.NotEqual(SocketError.AccessDenied, (await Connect("192.0.2.1")).Error);
    });

    [WfpLiveFact]
    public Task HigherWeightPermitWinsWithinTestSublayer() => WithCleanEngine(async engine =>
    {
        InstallGuarded(engine, [Rule("Subnet-Block", "192.0.2.0/24"),
            Rule("Host-Permit", "192.0.2.1/32") with { Action = WfpAction.Permit, Weight = 10 }]);
        Assert.NotEqual(SocketError.AccessDenied, (await Connect("192.0.2.1")).Error);
        await AssertBlocked("192.0.2.2");
    });

    [WfpLiveFact]
    public Task AppIdBlockAppliesToCurrentProcess() => WithCleanEngine(async engine =>
    {
        var program = Environment.ProcessPath;
        Assert.False(string.IsNullOrWhiteSpace(program), "需要当前测试进程的可执行文件路径。");
        InstallGuarded(engine, [Rule("App-Block", "192.0.2.1/32") with { AppPath = program }]);
        await AssertBlocked("192.0.2.1");
    });

    [WfpLiveFact]
    public Task PersistentFiltersSurviveEngineSessionAndCanBeRemovedByAnotherInstance() => WithCleanEngine(engine =>
    {
        var filter = Rule("Persistent", "192.0.2.1/32");
        InstallGuarded(engine, [filter]);
        var reopened = NewEngine(persistent: true);
        Assert.Equal(new[] { filter.Name }, reopened.ListFilterNames());
        reopened.Remove();
        Assert.Empty(reopened.ListFilterNames());
        return Task.CompletedTask;
    }, persistent: true);

    [WfpLiveFact]
    public Task RepeatedInstallLeavesExactlyOneCompleteSet() => WithCleanEngine(engine =>
    {
        WfpFilterSpec[] filters = [Rule("First", "192.0.2.1/32"), Rule("Second", "192.0.2.2/32")];
        InstallGuarded(engine, filters);
        InstallGuarded(engine, filters);
        var names = engine.ListFilterNames();
        Assert.Equal(2, names.Count);
        Assert.Equal(filters.Select(f => f.Name).Order(StringComparer.Ordinal), names.Order(StringComparer.Ordinal));
        return Task.CompletedTask;
    });

    private static WfpFilterSpec Rule(string suffix, string remote) => new(Prefix + suffix,
        WfpLayer.ConnectV4, WfpAction.Block, 0, RemoteAddresses: [remote], Protocol: "TCP", RemotePort: 9);

    // 唯一的 Install 入口：每次安装前逐条检查，任何遗漏地址或越界 CIDR 立即失败。
    private static void InstallGuarded(IWfpEngine engine, IReadOnlyList<WfpFilterSpec> filters)
    {
        Guard(filters);
        engine.Install(filters);
    }

    private static void Guard(IReadOnlyList<WfpFilterSpec> filters)
    {
        Assert.NotEmpty(filters);
        foreach (var filter in filters)
        {
            Assert.StartsWith(Prefix, filter.Name);
            Assert.Equal(WfpLayer.ConnectV4, filter.Layer);
            Assert.NotNull(filter.RemoteAddresses);
            Assert.NotEmpty(filter.RemoteAddresses);
            foreach (var cidr in filter.RemoteAddresses)
            {
                var parts = cidr.Split('/');
                Assert.Equal(2, parts.Length);
                Assert.True(IPAddress.TryParse(parts[0], out var address), "测试远端必须是合法地址。");
                Assert.Equal(AddressFamily.InterNetwork, address!.AddressFamily);
                Assert.True(int.TryParse(parts[1], out var prefix), "测试地址必须带合法前缀。");
                Assert.InRange(prefix, 24, 32);
                var bytes = address.GetAddressBytes();
                Assert.True(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2,
                    "安全闸拒绝安装：每条过滤器的全部远端地址必须落在 192.0.2.0/24 内。");
            }
        }
    }

    private static WfpEngine NewEngine(bool persistent) =>
        new(TestProviderKey, TestSublayerKey, "YuanC 测试保留地址过滤", persistent);

    private static async Task WithCleanEngine(Func<WfpEngine, Task> test, bool persistent = false)
    {
        Assert.True(OperatingSystem.IsWindows(), "真机过滤层测试需要 Windows 和管理员权限。");
        using var identity = WindowsIdentity.GetCurrent();
        Assert.True(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
            "已设 YUANC_WFP_LIVE=1，但当前进程不是管理员；请以管理员运行测试。");
        var engine = NewEngine(persistent);
        try
        {
            engine.Remove();
            await test(engine);
        }
        finally { engine.Remove(); }
    }

    private static async Task AssertBlocked(string address)
    {
        var result = await Connect(address);
        Assert.Equal(SocketError.AccessDenied, result.Error);
        Assert.True(result.Elapsed < TimeSpan.FromSeconds(3), "阻断必须在三秒内返回 AccessDenied。");
    }

    private static async Task<(SocketError Error, TimeSpan Elapsed)> Connect(string address)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var watch = Stopwatch.StartNew();
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(address), 9), timeout.Token);
            return (SocketError.Success, watch.Elapsed);
        }
        catch (SocketException ex) { return (ex.SocketErrorCode, watch.Elapsed); }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        { return (SocketError.TimedOut, watch.Elapsed); }
    }
}
