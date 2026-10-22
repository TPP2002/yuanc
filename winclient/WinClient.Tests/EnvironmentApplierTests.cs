using System.Diagnostics;
using System.Text.Json;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class EnvironmentApplierTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    public async Task ExitCodesMapToSafeErrorsAndRunnerUsesHiddenWindow(int exitCode)
    {
        using var temp = new TempDirectory();
        var runner = new Runner(exitCode);
        var applier = new EnvironmentApplier(temp.Path, runner);
        if (exitCode == 0) await applier.ApplyAsync(new("UTC", ["en"]));
        else if (exitCode == 4)
            Assert.Contains("连接与断网保护不受影响", (await Assert.ThrowsAsync<EnvironmentVerifyException>(() => applier.ApplyAsync(new("UTC", ["en"])))).Message);
        else
            Assert.Equal("环境一致性设置失败,原值记录已保留,请联系管理员。", (await Assert.ThrowsAsync<InvalidOperationException>(() => applier.ApplyAsync(new("UTC", ["en"])))).Message);
        Assert.True(runner.Start!.CreateNoWindow);
        Assert.False(runner.Start.UseShellExecute);
        Assert.True(runner.Cancellable);
        if (exitCode == 0) await applier.RestoreAsync();
        else if (exitCode == 4) await Assert.ThrowsAsync<EnvironmentVerifyException>(() => applier.RestoreAsync());
        else Assert.Equal("时区与浏览器设置未能恢复,原值记录已保留,请联系管理员。",
            (await Assert.ThrowsAsync<InvalidOperationException>(() => applier.RestoreAsync())).Message);
    }

    [Fact]
    public void PendingStateFollowsRecordFile()
    {
        using var temp = new TempDirectory();
        var applier = new EnvironmentApplier(temp.Path, new Runner(0));
        Assert.Equal(Path.Combine(temp.Path, "environment-state.json"), applier.StatePath);
        Assert.False(applier.HasPendingState);
        File.WriteAllText(applier.StatePath, "{}"); Assert.True(applier.HasPendingState);
        File.Delete(applier.StatePath); Assert.False(applier.HasPendingState);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{broken")]
    [InlineData("{}")]
    [InlineData("{\"enabled\":false,\"time_zone\":\"bad'\",\"languages\":[\"en\"]}")]
    [InlineData("{\"enabled\":false,\"time_zone\":\"UTC\",\"languages\":[]}")]
    [InlineData("{\"enabled\":\"false\",\"time_zone\":\"UTC\",\"languages\":[\"en\"]}")]
    public void MissingCorruptOrInvalidSettingsUseCompleteDefault(string? content)
    {
        using var temp = new TempDirectory();
        if (content is not null) File.WriteAllText(Path.Combine(temp.Path, "environment.json"), content);
        var policy = new EnvironmentSettingsStore(temp.Path).Read();
        Assert.True(policy.Enabled);
        Assert.Equal("AUS Eastern Standard Time", policy.Target.TimeZoneId);
        Assert.Equal(new[] { "en-AU", "en" }, policy.Target.Languages);
    }

    [Fact]
    public void WriteEnabledPreservesAdministratorTargetAndOtherFields()
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "environment.json");
        File.WriteAllText(path, "{\"enabled\":true,\"time_zone\":\"W. Australia Standard Time\",\"languages\":[\"en-AU\"],\"note\":\"保留\"}");
        var store = new EnvironmentSettingsStore(temp.Path);
        store.WriteEnabled(false);
        var policy = store.Read();
        Assert.False(policy.Enabled);
        Assert.Equal("W. Australia Standard Time", policy.Target.TimeZoneId);
        Assert.Equal(new[] { "en-AU" }, policy.Target.Languages);
        using var json = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal("保留", json.RootElement.GetProperty("note").GetString());
        Assert.False(File.Exists(path + ".tmp"));
    }

    private sealed class Runner(int exitCode) : ICommandRunner
    {
        public ProcessStartInfo? Start { get; private set; }
        public bool Cancellable { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        { Start = startInfo; Cancellable = cancellationToken.CanBeCanceled; return Task.FromResult(new CommandResult(exitCode, "不可写入日志的输出")); }
    }
}
