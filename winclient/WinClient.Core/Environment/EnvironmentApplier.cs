using WinClient.Core.Firewall;
using System.Text.Json;

namespace WinClient.Core.EnvironmentSupport;

public sealed record EnvironmentInspection(string TimeZone, int? AutoTimeZoneStart,
    IReadOnlyDictionary<string, string?> Chrome, IReadOnlyDictionary<string, string?> Edge, string[] ChromeForcedLanguages);

public interface IEnvironmentEnforcer
{
    bool HasPendingState { get; }
    Task ApplyAsync(EnvironmentTarget target);
    Task RestoreAsync();
    Task<EnvironmentInspection?> InspectAsync() => Task.FromResult<EnvironmentInspection?>(null);
}

public sealed class EnvironmentVerifyException(string message) : InvalidOperationException(message);

public sealed class EnvironmentApplier(string runDirectory, ICommandRunner? runner = null) : IEnvironmentEnforcer
{
    private readonly ICommandRunner runner = runner ?? new CommandRunner();
    private readonly SemaphoreSlim gate = new(1, 1);
    public string StatePath { get; } = Path.Combine(runDirectory, "environment-state.json");
    public bool HasPendingState => File.Exists(StatePath);
    public Task ApplyAsync(EnvironmentTarget target) => ExecuteAsync(EnvironmentPlanner.ApplyScript(target, StatePath), restoring: false);
    public Task RestoreAsync() => ExecuteAsync(EnvironmentPlanner.RestoreScript(StatePath), restoring: true);

    public async Task<EnvironmentInspection?> InspectAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var result = await runner.RunAsync(KillSwitchApplier.CreateStartInfo(EnvironmentPlanner.InspectScript()), timeout.Token).ConfigureAwait(false);
            if (result.ExitCode != 0) return null;
            var lastLine = result.Output.Split('\n').LastOrDefault(line => !string.IsNullOrWhiteSpace(line));
            if (lastLine is null) return null;
            using var json = JsonDocument.Parse(lastLine);
            var root = json.RootElement;
            var chrome = root.GetProperty("chrome");
            var edge = root.GetProperty("edge");
            static string? Value(JsonElement obj, string key) => obj.TryGetProperty(key, out var value)
                && value.ValueKind != JsonValueKind.Null ? value.ToString() : null;
            var autoStart = root.GetProperty("tzautoupdate_start");
            var languages = chrome.TryGetProperty("forced_languages", out var forced)
                ? forced.EnumerateArray().Select(item => item.GetString() ?? throw new JsonException()).ToArray() : [];
            return new(root.GetProperty("time_zone").GetString() ?? throw new JsonException(),
                autoStart.ValueKind == JsonValueKind.Null ? null : autoStart.GetInt32(),
                new Dictionary<string, string?>
                {
                    ["ForcedLanguages"] = null, ["WebRtcIPHandling"] = Value(chrome, "WebRtcIPHandling"),
                    ["DefaultGeolocationSetting"] = Value(chrome, "DefaultGeolocationSetting")
                },
                new Dictionary<string, string?>
                {
                    ["DefinePreferredLanguages"] = Value(edge, "DefinePreferredLanguages"),
                    ["WebRtcLocalhostIpHandling"] = Value(edge, "WebRtcLocalhostIpHandling"),
                    ["DefaultGeolocationSetting"] = Value(edge, "DefaultGeolocationSetting")
                }, languages);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
            JsonException or KeyNotFoundException or FormatException or OverflowException or ArgumentException or
            OperationCanceledException or System.ComponentModel.Win32Exception)
        { return null; }
        finally { gate.Release(); }
    }

    private async Task ExecuteAsync(string script, bool restoring)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            // 复用隐藏窗口的既有执行器，不记录脚本输出或异常中的系统信息。
            var result = await runner.RunAsync(KillSwitchApplier.CreateStartInfo(script), timeout.Token).ConfigureAwait(false);
            if (result.ExitCode == 4)
                throw new EnvironmentVerifyException("时区切换未生效,可能被组策略锁定;连接与断网保护不受影响。");
            if (result.ExitCode != 0)
                throw new InvalidOperationException(restoring
                    ? "时区与浏览器设置未能恢复,原值记录已保留,请联系管理员。"
                    : "环境一致性设置失败,原值记录已保留,请联系管理员。");
        }
        finally { gate.Release(); }
    }
}
