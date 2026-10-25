using System.Diagnostics;
using System.Text.RegularExpressions;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

public sealed class NicGuardTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "nicguard-" + Guid.NewGuid().ToString("N"));
    private string StatePath => Path.Combine(directory, "nic-guard-state.json");
    public NicGuardTests() => Directory.CreateDirectory(directory);
    public void Dispose() { try { Directory.Delete(directory, true); } catch (IOException) { } }

    internal static AdapterInfo Nic(string name, string[] ipv4, string[] ipv6) =>
        new(name, name, ipv4.Select(x => new AdapterAddress(x, 24)).ToArray()) { Ipv6 = ipv6.Select(x => new AdapterAddress(x, 64)).ToArray() };

    /// <summary>同时扮演网卡探针与命令运行器：关闭绑定后对应网卡的 IPv6 地址从快照里消失。</summary>
    internal sealed class World : IAdapterProbe, ICommandRunner
    {
        public List<AdapterInfo>? Adapters { get; set; } = [];
        public HashSet<string> Disabled { get; } = [];
        public List<ProcessStartInfo> Starts { get; } = [];
        public List<string> Scripts { get; } = [];
        public bool DisableTakesEffect { get; set; } = true;
        public int DisableExitCode { get; set; }
        public HashSet<string> FailEnable { get; } = [];
        public bool Throw { get; set; }
        public Action<string>? OnRun { get; set; }
        public IReadOnlyList<AdapterInfo>? Snapshot() => Adapters?.Select(a => Disabled.Contains(a.Name) ? a with { Ipv6 = [] } : a).ToArray();
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            var script = startInfo.ArgumentList.Last();
            Starts.Add(startInfo); Scripts.Add(script); OnRun?.Invoke(script);
            if (Throw) throw new InvalidOperationException("模拟运行器异常");
            var exit = 0;
            foreach (Match m in Regex.Matches(script, @"Disable-NetAdapterBinding -Name '((?:[^']|'')*)'"))
            {
                if (DisableTakesEffect) Disabled.Add(m.Groups[1].Value.Replace("''", "'"));
                exit = DisableExitCode;
            }
            foreach (Match m in Regex.Matches(script, @"Enable-NetAdapterBinding -Name '((?:[^']|'')*)'"))
            {
                var name = m.Groups[1].Value.Replace("''", "'");
                if (FailEnable.Contains(name)) exit = 1; else Disabled.Remove(name);
            }
            return Task.FromResult(new CommandResult(exit, ""));
        }
    }

    private NicGuard Guard(World world, Action? onDelay = null) =>
        new(directory, world, world, (_, _) => { onDelay?.Invoke(); return Task.CompletedTask; });

    private static World Standard() => new()
    {
        Adapters =
        [
            Nic("以太网", ["192.168.1.5"], ["240e::1", "fe80::1"]),
            Nic("Wi-Fi", ["192.168.2.5"], ["fe80::2"]),
            Nic(KillSwitchPlanner.TunAlias, ["172.19.0.1"], ["240e::99"])
        ]
    };

    [Fact]
    public async Task ApplyDisablesOnlyAdaptersWithPublicIpv6()
    {
        var world = Standard();
        // 名为 YuanC-TUN 且有公网 IPv6 的网卡属于隧道自身,不能被处理。
        Assert.Contains("YuanC-TUN", world.Adapters!.Select(a => a.Name));
        await Guard(world).ApplyAsync(CancellationToken.None);
        Assert.Equal(new[] { "以太网" }, world.Disabled.ToArray());
        var script = Assert.Single(world.Scripts);
        Assert.Contains("Disable-NetAdapterBinding -Name '以太网' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop", script);
        Assert.DoesNotContain("Wi-Fi", script);
        Assert.DoesNotContain(KillSwitchPlanner.TunAlias, script);
        Assert.Contains("\"disabled\":[\"以太网\"]", File.ReadAllText(StatePath));
    }

    [Fact]
    public async Task ApplyDoesNothingWithoutPublicIpv6()
    {
        var world = new World { Adapters = [Nic("以太网", ["192.168.1.5"], ["fe80::1"])] };
        var guard = Guard(world);
        await guard.ApplyAsync(CancellationToken.None);
        Assert.Empty(world.Scripts);
        Assert.False(File.Exists(StatePath));
        Assert.False(guard.HasPendingState);
    }

    [Fact]
    public async Task ApplyUnionsExistingRecordAndQuotesNames()
    {
        File.WriteAllText(StatePath, "{\"disabled\":[\"旧网卡\"]}");
        var world = new World { Adapters = [Nic("Bob's NIC", [], ["240e::7"])] };
        await Guard(world).ApplyAsync(CancellationToken.None);
        var record = File.ReadAllText(StatePath);
        Assert.Contains("旧网卡", record);
        Assert.Contains("Bob's NIC", record);
        Assert.Contains("-Name 'Bob''s NIC'", Assert.Single(world.Scripts));
        Assert.False(File.Exists(StatePath + ".tmp"));
    }

    [Fact]
    public async Task ApplyWritesRecordBeforeDisabling()
    {
        var world = Standard();
        var seen = false;
        world.OnRun = _ => seen = File.Exists(StatePath) && File.ReadAllText(StatePath).Contains("以太网");
        await Guard(world).ApplyAsync(CancellationToken.None);
        Assert.True(seen);
    }

    [Fact]
    public async Task ApplyThrowsWhenPublicIpv6Remains()
    {
        var world = Standard();
        world.DisableTakesEffect = false;
        var delays = 0;
        var error = await Assert.ThrowsAsync<NicGuardException>(() => Guard(world, () => delays++).ApplyAsync(CancellationToken.None));
        Assert.Equal("未能关闭网卡「以太网」的 IPv6,其公网 IPv6 地址可能被网页读到,已拒绝连接。请点击断开后重试,仍失败请联系管理员。", error.Message);
        Assert.Equal("以太网", error.AdapterName);
        Assert.Equal(10, delays);
        Assert.DoesNotContain("240e", error.Message);
        Assert.True(File.Exists(StatePath));
    }

    [Fact]
    public async Task ApplyThrowsWhenScriptFails()
    {
        var world = Standard();
        world.DisableExitCode = 1;
        var error = await Assert.ThrowsAsync<NicGuardException>(() => Guard(world).ApplyAsync(CancellationToken.None));
        Assert.Contains("「以太网」", error.Message);
    }

    [Fact]
    public async Task RestoreEnablesOnlyRecordedAdapters()
    {
        File.WriteAllText(StatePath, "{\"disabled\":[\"以太网\"]}");
        var world = Standard();
        world.Disabled.Add("以太网"); world.Disabled.Add("别的网卡");
        var guard = Guard(world);
        Assert.True(guard.HasPendingState);
        Assert.Null(await guard.RestoreAsync());
        Assert.DoesNotContain("以太网", world.Disabled);
        Assert.Contains("别的网卡", world.Disabled);
        Assert.All(world.Scripts, script => Assert.DoesNotContain("别的网卡", script));
        Assert.Contains(world.Scripts, script => script.Contains("Enable-NetAdapterBinding -Name '以太网' -ComponentID ms_tcpip6 -Confirm:$false"));
        Assert.False(File.Exists(StatePath));
        Assert.False(guard.HasPendingState);
    }

    [Fact]
    public async Task RestoreWithoutRecordReturnsNullAndRunsNothing()
    {
        var world = Standard();
        Assert.Null(await Guard(world).RestoreAsync());
        Assert.Empty(world.Scripts);
    }

    [Fact]
    public async Task RestoreKeepsRecordOnPartialFailure()
    {
        File.WriteAllText(StatePath, "{\"disabled\":[\"A\",\"B\",\"C\"]}");
        var world = new World();
        world.FailEnable.Add("B"); world.FailEnable.Add("C");
        var warning = await Guard(world).RestoreAsync();
        Assert.Equal("网卡「B、C」的 IPv6 未能恢复,请重试断开或联系管理员。", warning);
        var record = File.ReadAllText(StatePath);
        Assert.Contains("B", record); Assert.Contains("C", record); Assert.DoesNotContain("\"A\"", record);
    }

    [Fact]
    public async Task RestoreTreatsRunnerExceptionAsFailureWithoutThrowing()
    {
        File.WriteAllText(StatePath, "{\"disabled\":[\"A\"]}");
        var world = new World { Throw = true };
        var warning = await Guard(world).RestoreAsync();
        Assert.Equal("网卡「A」的 IPv6 未能恢复,请重试断开或联系管理员。", warning);
        Assert.True(File.Exists(StatePath));
    }

    [Fact]
    public async Task PatrolDisablesNewlyAppearedAdapters()
    {
        var world = new World { Adapters = [Nic("以太网", ["192.168.1.5"], ["fe80::1"])] };
        var guard = Guard(world);
        var quiet = await guard.PatrolAsync(CancellationToken.None);
        Assert.Empty(quiet.NewlyDisabled); Assert.Empty(quiet.PublicIpv4Adapters);
        Assert.Empty(world.Scripts);
        world.Adapters!.Add(Nic("新网卡", ["8.8.4.4"], ["2400:1::5"]));
        world.Adapters.Add(Nic(KillSwitchPlanner.TunAlias, ["172.19.0.1"], ["2400:1::6"]));
        var report = await guard.PatrolAsync(CancellationToken.None);
        Assert.Equal(new[] { "新网卡" }, report.NewlyDisabled);
        Assert.Equal(new[] { "新网卡" }, report.PublicIpv4Adapters);
        Assert.Contains("新网卡", File.ReadAllText(StatePath));
        var again = await guard.PatrolAsync(CancellationToken.None);
        Assert.Empty(again.NewlyDisabled);
    }

    [Fact]
    public async Task PatrolThrowsRetainedTunnelMessageWhenDisableFails()
    {
        var world = new World { Adapters = [Nic("以太网", [], ["240e::1"])], DisableTakesEffect = false };
        var error = await Assert.ThrowsAsync<NicGuardException>(() => Guard(world).PatrolAsync(CancellationToken.None));
        Assert.Equal("未能关闭网卡「以太网」的 IPv6,隧道保持,但该网卡的公网 IPv6 地址可能被网页读到;请联系管理员。", error.Message);
    }

    [Fact]
    public void PublicIpv4AdapterSkipsTunnelAndThrowsWithoutSnapshot()
    {
        var world = new World { Adapters = [Nic(KillSwitchPlanner.TunAlias, ["8.8.8.8"], []), Nic("私网", ["10.0.0.2"], []), Nic("拨号", ["1.2.3.4"], [])] };
        Assert.Equal("拨号", Guard(world).PublicIpv4Adapter());
        world.Adapters = [Nic("私网", ["10.0.0.2"], [])];
        Assert.Null(Guard(world).PublicIpv4Adapter());
        world.Adapters = null;
        Assert.Equal("无法读取网卡地址", Assert.Throws<InvalidOperationException>(() => Guard(world).PublicIpv4Adapter()).Message);
    }

    [Fact]
    public async Task ScriptsRunHidden()
    {
        File.WriteAllText(StatePath, "{\"disabled\":[\"旧\"]}");
        var world = Standard();
        var guard = Guard(world);
        await guard.ApplyAsync(CancellationToken.None);
        await guard.RestoreAsync();
        Assert.NotEmpty(world.Starts);
        Assert.All(world.Starts, start =>
        {
            Assert.True(start.CreateNoWindow);
            Assert.False(start.UseShellExecute);
            Assert.Equal(ProcessWindowStyle.Hidden, start.WindowStyle);
            Assert.Contains("-NoProfile", start.ArgumentList);
            Assert.Contains("-NonInteractive", start.ArgumentList);
            Assert.Contains("Bypass", start.ArgumentList);
            Assert.Contains("ms_tcpip6", start.ArgumentList.Last());
        });
    }
}
