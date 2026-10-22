using System.Diagnostics;
using System.Text.Json;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;
using Xunit;

namespace WinClient.Tests;

public sealed class EnvironmentApplierTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ForceRestoreSelectsRecordOrFallbackAndKeepsHiddenRunner(bool record)
    {
        using var temp = new TempDirectory();
        var runner = new Runner(0);
        var applier = new EnvironmentApplier(temp.Path, runner);
        if (record) File.WriteAllText(applier.StatePath, "{}");
        await applier.ForceRestoreAsync(new("UTC", ["en"]));
        var script = runner.Start!.ArgumentList.Last();
        if (record) Assert.Contains("Remove-Item -LiteralPath $statePath", script);
        else
        {
            Assert.Contains("Start-Service tzautoupdate", script);
            Assert.DoesNotContain("$statePath", script);
        }
        Assert.True(runner.Start.CreateNoWindow);
        Assert.False(runner.Start.UseShellExecute);
        Assert.True(runner.Cancellable);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public async Task ForceRestoreFallbackFailureUsesDefaultSettingsError(int exitCode)
    {
        using var temp = new TempDirectory();
        var applier = new EnvironmentApplier(temp.Path, new Runner(exitCode));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => applier.ForceRestoreAsync(new("UTC", ["en"])));
        Assert.Contains("未能恢复默认设置", error.Message);
    }

    [Theory]
    [InlineData("AU", "AU")]
    [InlineData("NZ", "NZ")]
    [InlineData("au", "AU")]
    [InlineData("AUS", "AU")]
    [InlineData(null, "AU")]
    public void CountryUsesUppercasePairOrDefaultWithoutLosingOtherSettings(string? country, string expected)
    {
        using var temp = new TempDirectory();
        File.WriteAllText(Path.Combine(temp.Path, "environment.json"), JsonSerializer.Serialize(new
            { enabled = false, time_zone = "UTC", languages = new[] { "en" }, country }));
        var store = new EnvironmentSettingsStore(temp.Path);
        Assert.Equal(expected, store.Read().ExpectedCountry);
        Assert.False(store.Read().Enabled); Assert.Equal("UTC", store.Read().Target.TimeZoneId);
        store.WriteEnabled(true);
        Assert.Equal(expected, store.Read().ExpectedCountry);
    }

    [Fact]
    public async Task InspectReadsLastNonemptyJsonLineAndNormalizesValues()
    {
        using var temp = new TempDirectory();
        var runner = new InspectionRunner(0, "提示\n" + """
            {"time_zone":"AUS Eastern Standard Time","tzautoupdate_start":4,
            "chrome":{"forced_languages":["en-AU","en"],"WebRtcIPHandling":"default_public_interface_only","DefaultGeolocationSetting":2,"DnsOverHttpsMode":"secure","DnsOverHttpsTemplates":"https://1.1.1.1/dns-query"},
            "edge":{"DefinePreferredLanguages":"en-AU,en","DefaultGeolocationSetting":2,"DnsOverHttpsMode":"secure"}}
            """.Replace("\n", "") + "\n\n");
        var inspection = await new EnvironmentApplier(temp.Path, runner).InspectAsync();
        Assert.NotNull(inspection);
        Assert.Equal("AUS Eastern Standard Time", inspection.TimeZone);
        Assert.Equal(4, inspection.AutoTimeZoneStart);
        Assert.Equal(new[] { "en-AU", "en" }, inspection.ChromeForcedLanguages);
        Assert.Equal("2", inspection.Chrome["DefaultGeolocationSetting"]);
        Assert.Equal("2", inspection.Edge["DefaultGeolocationSetting"]);
        Assert.Null(inspection.Edge["WebRtcLocalhostIpHandling"]);
        Assert.Equal("https://1.1.1.1/dns-query", inspection.Chrome["DnsOverHttpsTemplates"]);
        Assert.Null(inspection.Edge["DnsOverHttpsTemplates"]);
        Assert.Equal(5, inspection.Chrome.Count); Assert.Equal(5, inspection.Edge.Count);
        Assert.True(runner.Start!.CreateNoWindow);
    }

    [Theory]
    [InlineData(1, "{}")]
    [InlineData(0, "坏 JSON")]
    [InlineData(0, "")]
    public async Task FailedInspectionReturnsNull(int exitCode, string output)
    {
        using var temp = new TempDirectory();
        Assert.Null(await new EnvironmentApplier(temp.Path, new InspectionRunner(exitCode, output)).InspectAsync());
    }

    [Fact]
    public async Task InspectReturnsNullWhenCancelled()
    {
        using var temp = new TempDirectory();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var runner = new CancelledInspectionRunner();
        Assert.Null(await new EnvironmentApplier(temp.Path, runner).InspectAsync(cancelled.Token));
        Assert.True(runner.Token.IsCancellationRequested);
    }

    private sealed class CancelledInspectionRunner : ICommandRunner
    {
        public CancellationToken Token { get; private set; }
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        {
            Token = cancellationToken;
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("巡查必须收到已取消令牌。");
        }
    }

    private sealed class InspectionRunner(int exitCode, string output) : ICommandRunner
    {
        public ProcessStartInfo? Start;
        public Task<CommandResult> RunAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken = default)
        { Start = startInfo; return Task.FromResult(new CommandResult(exitCode, output)); }
    }

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
