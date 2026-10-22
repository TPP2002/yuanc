using WinClient.Core.Firewall;

namespace WinClient.Core.EnvironmentSupport;

public interface IEnvironmentEnforcer
{
    bool HasPendingState { get; }
    Task ApplyAsync(EnvironmentTarget target);
    Task RestoreAsync();
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
