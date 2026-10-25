using System.Diagnostics;
using System.Net;
using System.Text.Json;
using WinClient.Core.Diagnostics;
using WinClient.Core.Firewall;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

public sealed class LeakCaptureTests
{
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.5");
    private static readonly IPAddress NodeIp = IPAddress.Parse("13.237.1.2");
    private const string Google = "74.125.250.129";

    private static CapturedPacket Tcp(string src, string dst, int sp, int dp) =>
        new(1, IPAddress.Parse(src), IPAddress.Parse(dst), "TCP", sp, dp);
    private static CapturedPacket Udp(string src, string dst, int sp, int dp) =>
        new(1, IPAddress.Parse(src), IPAddress.Parse(dst), "UDP", sp, dp);

    private static LeakContext Context(IPEndPoint? auth = null, bool apps = false, params string[] list) =>
        new(new HashSet<IPAddress> { Local, IPAddress.Parse("2409:8a00::5") },
            new HashSet<IPAddress> { NodeIp }, auth, apps, list);

    [Fact]
    public void TunnelAndLanAndNodeTrafficIsAllowed()
    {
        var verdict = LeakClassifier.Classify(
        [
            Tcp("172.19.0.1", "8.8.8.8", 1000, 443),
            Tcp("192.168.1.5", "192.168.1.1", 2000, 445),
            Tcp("192.168.1.5", "13.237.1.2", 3000, 443),
            new CapturedPacket(1, IPAddress.Parse("fdfe:dcba:9876::1"), IPAddress.Parse("2606:4700::1111"), "UDP", 1, 2),
            new CapturedPacket(1, null, null, "OTHER", 0, 0)
        ], Context(), _ => null);
        Assert.Equal(5, verdict.Total);
        Assert.Equal(2, verdict.Tunnel);
        Assert.Equal(2, verdict.Allowed);
        Assert.Equal(1, verdict.Unparsed);
        Assert.Empty(verdict.Suspicious);
    }

    [Fact]
    public void PublicNonNodeTrafficIsSuspicious()
    {
        var verdict = LeakClassifier.Classify(
        [
            Udp("192.168.1.5", Google, 50000, 19302), Udp("192.168.1.5", Google, 50000, 19302),
            Tcp(Google, "192.168.1.5", 443, 50100), Tcp("192.168.1.5", "8.8.8.8", 50200, 443)
        ], Context(), packet => packet.SourcePort == 50000 ? "C:\\Apps\\chrome.exe" : null);
        Assert.Equal(3, verdict.Suspicious.Count);
        var stun = Assert.Single(verdict.Suspicious, flow => flow.RemotePort == 19302);
        Assert.Equal(new SuspiciousFlow("UDP", Google, 19302, "C:\\Apps\\chrome.exe", null, 2), stun);
        Assert.Contains(verdict.Suspicious, flow => flow.Remote == Google && flow.RemotePort == 443 && flow.Process is null);
        Assert.Equal(0, verdict.Allowed);
    }

    [Fact]
    public void AuthAllowedOnlyOnItsPort()
    {
        var auth = new IPEndPoint(IPAddress.Parse("52.1.1.1"), 8443);
        var verdict = LeakClassifier.Classify(
        [
            Tcp("192.168.1.5", "52.1.1.1", 1, 8443), Tcp("192.168.1.5", "52.1.1.1", 2, 443),
            Udp("192.168.1.5", "52.1.1.1", 3, 8443)
        ], Context(auth), _ => null);
        Assert.Equal(1, verdict.Allowed);
        Assert.Equal(2, verdict.Suspicious.Count);
        Assert.DoesNotContain(verdict.Suspicious, flow => flow.Protocol == "TCP" && flow.RemotePort == 8443);
    }

    [Fact]
    public void LocalAddressesNeverAppearInVerdict()
    {
        var verdict = LeakClassifier.Classify(
        [
            Tcp(Google, "192.168.1.5", 443, 50100),
            Udp("192.168.1.5", "192.168.1.5", 1, 2),
            new CapturedPacket(1, IPAddress.Parse("2409:8a00::5"), IPAddress.Parse("2409:8a00::5"), "TCP", 1, 2),
            new CapturedPacket(1, IPAddress.Parse("2409:8a00::5"), IPAddress.Parse("2606:4700::1111"), "TCP", 1, 443)
        ], Context(), _ => null);
        var json = JsonSerializer.Serialize(verdict);
        Assert.DoesNotContain("192.168.1.5", json);
        Assert.DoesNotContain("2409:8a00", json);
        Assert.Equal(2, verdict.Suspicious.Count);
    }

    [Fact]
    public void AppsModeMarksListedAndUnlisted()
    {
        var context = Context(null, true, "C:\\Apps\\Chat\\chat.exe");
        var owners = new Dictionary<int, string?>
        {
            [1] = "c:\\apps\\chat\\CHAT.EXE", [2] = "C:\\Apps\\Chat\\helper\\child.exe",
            [3] = "C:\\Other\\browser.exe", [4] = null
        };
        var verdict = LeakClassifier.Classify(
            owners.Keys.Select(port => Tcp("192.168.1.5", "8.8.8.8", port, 443)), context, packet => owners[packet.SourcePort]);
        Assert.Equal(true, verdict.Suspicious.Single(flow => flow.Process == owners[1]).Listed);
        Assert.Equal(true, verdict.Suspicious.Single(flow => flow.Process == owners[2]).Listed);
        Assert.Equal(false, verdict.Suspicious.Single(flow => flow.Process == owners[3]).Listed);
        Assert.Null(verdict.Suspicious.Single(flow => flow.Process is null).Listed);
    }

    [Fact]
    public async Task StopsPktmonEvenWhenConversionFails()
    {
        using var dir = new TempDirectory();
        var runner = new FakeRunner { FailOn = "etl2pcap" };
        var result = await Capture(runner).RunAsync(Options(dir.Path), CancellationToken.None);
        Assert.Equal(2, result.ExitCode);
        Assert.NotNull(result.Reason);
        Assert.Equal(1, runner.Count("stop"));
        Assert.Equal(["filter", "start", "stop", "etl2pcap"], runner.Verbs);

        var startFails = new FakeRunner { FailOn = "start" };
        Assert.Equal(2, (await Capture(startFails).RunAsync(Options(dir.Path), CancellationToken.None)).ExitCode);
        Assert.Equal(0, startFails.Count("stop"));
        Assert.Contains("--comp", runner.Calls.Single(call => call.ArgumentList[0] == "start").ArgumentList);
    }

    [Fact]
    public async Task ExitCodeReflectsVerdict()
    {
        using var dir = new TempDirectory();
        var clean = new FakeRunner { Pcap = Pcap(PcapBuilder.EthernetV4("192.168.1.5", "13.237.1.2", 6, 1, 443)) };
        Assert.Equal(0, (await Capture(clean).RunAsync(Options(dir.Path), CancellationToken.None)).ExitCode);
        var leak = new FakeRunner { Pcap = Pcap(PcapBuilder.EthernetV4("192.168.1.5", Google, 17, 1, 19302)) };
        Assert.Equal(1, (await Capture(leak).RunAsync(Options(dir.Path), CancellationToken.None)).ExitCode);
        var apps = Options(dir.Path) with { AppsMode = true, Apps = ["C:\\Apps\\chat.exe"] };
        var unlisted = new FakeRunner { Pcap = leak.Pcap };
        var table = new FakeTcp([new TcpEntry(5, Local, 1, IPAddress.Parse(Google), 19302, 9, "C:\\Other\\x.exe")]);
        var udp = new FakeUdp([new UdpEntry(Local, 1, 9, "C:\\Other\\x.exe")]);
        Assert.Equal(0, (await new LeakCapture(unlisted, table, udp, () => new HashSet<IPAddress> { Local }, NoDelay)
            .RunAsync(apps, CancellationToken.None)).ExitCode);
        var unknown = await Capture(new FakeRunner { Pcap = leak.Pcap }).RunAsync(apps, CancellationToken.None);
        Assert.Equal(1, unknown.ExitCode);
        var noNode = Options(dir.Path) with { Node = null };
        var missing = await Capture(clean).RunAsync(noNode, CancellationToken.None);
        Assert.Equal(2, missing.ExitCode);
        Assert.Equal("未找到隧道内核的连接，请先连接，或用 --node 指定节点地址", missing.Reason);
    }

    [Fact]
    public async Task ProcessesRunHidden()
    {
        using var dir = new TempDirectory();
        var runner = new FakeRunner();
        await Capture(runner).RunAsync(Options(dir.Path), CancellationToken.None);
        Assert.Equal(4, runner.Calls.Count);
        Assert.All(runner.Calls, info =>
        {
            Assert.True(info.CreateNoWindow);
            Assert.False(info.UseShellExecute);
            Assert.Equal(ProcessWindowStyle.Hidden, info.WindowStyle);
            Assert.EndsWith("pktmon.exe", info.FileName, StringComparison.OrdinalIgnoreCase);
        });
        Assert.Empty(Directory.GetFiles(dir.Path)); // 默认检测后删除抓包文件
    }

    private static Task NoDelay(TimeSpan span, CancellationToken token) => Task.CompletedTask;
    private static byte[] Pcap(params byte[][] frames) =>
        PcapBuilder.File(new[] { PcapBuilder.Shb(), PcapBuilder.Idb(1) }.Concat(frames.Select(f => PcapBuilder.Epb(f))).ToArray());
    private static LeakCheckOptions Options(string dir) => new(1, "13.237.1.2", dir, false, false, [], null);
    private static LeakCapture Capture(FakeRunner runner) =>
        new(runner, new FakeTcp([]), new FakeUdp([]), () => new HashSet<IPAddress> { Local }, NoDelay);

    private sealed class FakeTcp(IReadOnlyList<TcpEntry> rows) : ITcpTable
    {
        public IReadOnlyList<TcpEntry> Snapshot() => rows;
        public bool Reset(TcpEntry entry) => false;
    }

    private sealed class FakeUdp(IReadOnlyList<UdpEntry> rows) : IUdpTable
    {
        public IReadOnlyList<UdpEntry> Snapshot() => rows;
    }

    private sealed class FakeRunner : ICommandRunner
    {
        public string? FailOn { get; init; }
        public byte[] Pcap { get; init; } = LeakCaptureTests.Pcap();
        public List<ProcessStartInfo> Calls { get; } = [];
        public List<string> Verbs => Calls.Select(call => call.ArgumentList[0]).ToList();
        public int Count(string verb) => Verbs.Count(value => value == verb);

        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            Calls.Add(startInfo);
            var verb = startInfo.ArgumentList[0];
            if (verb == FailOn) return Task.FromResult(new CommandResult(1, ""));
            if (verb == "etl2pcap")
                File.WriteAllBytes(startInfo.ArgumentList[startInfo.ArgumentList.IndexOf("--out") + 1], Pcap);
            if (verb == "start")
                File.WriteAllText(startInfo.ArgumentList[startInfo.ArgumentList.IndexOf("--file-name") + 1], "etl");
            return Task.FromResult(new CommandResult(0, ""));
        }
    }
}
