using System.Diagnostics;
using WinClient.Core.Diagnostics;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public class FirewallStateProbeTests
{
    [Fact]
    public void ScriptIsReadOnly()
    {
        foreach (var word in new[] { "Set-", "Enable-", "Disable-", "New-", "Remove-", "Stop-", "Start-", "Restart-", "netsh" })
            Assert.DoesNotContain(word, FirewallStateProbe.Script);
        Assert.Contains("Get-NetFirewallProfile", FirewallStateProbe.Script);
        Assert.Contains("MpsSvc", FirewallStateProbe.Script);
        Assert.Contains("YuanC-KS-*", FirewallStateProbe.Script);
        Assert.Contains("ConvertTo-Json", FirewallStateProbe.Script);
    }

    [Fact]
    public async Task RunUsesHiddenWindowStartInfo()
    {
        var runner = new FakeRunner((_, _) => Task.FromResult(new CommandResult(0, "{\"service\":\"Running\"}")));
        _ = await FirewallStateProbe.RunAsync(runner);
        Assert.NotNull(runner.StartInfo);
        Assert.True(runner.StartInfo!.CreateNoWindow);
        Assert.False(runner.StartInfo.UseShellExecute);
    }

    [Fact]
    public async Task ReturnsLastJsonLine()
    {
        var runner = new FakeRunner((_, _) =>
            Task.FromResult(new CommandResult(0, "警告\n{\"service\":\"Running\"}\n")));
        var result = await FirewallStateProbe.RunAsync(runner);
        Assert.Equal("{\"service\":\"Running\"}", result.Json);
        Assert.Null(result.Error);
    }

    [Theory]
    [InlineData(1, "{\"service\":\"Running\"}")]
    [InlineData(0, "not json")]
    [InlineData(0, "[1,2,3]")]
    public async Task NonZeroExitOrBadJsonReportsFailed(int exitCode, string output)
    {
        var runner = new FakeRunner((_, _) => Task.FromResult(new CommandResult(exitCode, output)));
        var result = await FirewallStateProbe.RunAsync(runner);
        Assert.Null(result.Json);
        Assert.Equal(FirewallStateProbe.Failed, result.Error);
    }

    [Fact]
    public async Task TimeoutReportsTimedOut()
    {
        var runner = new FakeRunner(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new CommandResult(0, "{}");
        });
        var result = await FirewallStateProbe.RunAsync(runner, TimeSpan.FromMilliseconds(50));
        Assert.Null(result.Json);
        Assert.Equal(FirewallStateProbe.TimedOut, result.Error);
    }

    [Fact]
    public async Task ExternalCancelStillThrows()
    {
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        var runner = new FakeRunner((_, token) =>
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult(new CommandResult(0, "{}"));
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            FirewallStateProbe.RunAsync(runner, TimeSpan.FromSeconds(5), cancel.Token));
    }

    private sealed class FakeRunner(Func<ProcessStartInfo, CancellationToken, Task<CommandResult>> behavior) : ICommandRunner
    {
        public ProcessStartInfo? StartInfo { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            StartInfo = startInfo;
            return behavior(startInfo, cancellationToken);
        }
    }
}
