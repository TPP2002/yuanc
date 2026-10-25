using System.Diagnostics;
using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using WinClient.Core.EnvironmentSupport;
using WinClient.Core.Firewall;

namespace WinClient.Core.Network;

/// <summary>关闭网卡 IPv6 绑定失败。AdapterName 只带网卡名,不含任何地址。</summary>
public sealed class NicGuardException(string message) : FirewallIneffectiveException(message)
{
    public string? AdapterName { get; init; }
}

public sealed record NicPatrolReport(IReadOnlyList<string> NewlyDisabled, IReadOnlyList<string> PublicIpv4Adapters);

public interface INicGuard
{
    bool HasPendingState { get; }
    string? PublicIpv4Adapter();
    Task ApplyAsync(CancellationToken token);
    Task<NicPatrolReport> PatrolAsync(CancellationToken token);
    Task<string?> RestoreAsync();
}

/// <summary>
/// 连接期间关闭带公网 IPv6 的网卡的 IPv6 绑定(断开时恢复),并检出网卡上的公网 IPv4。
/// 记录文件先于关闭写入,服务崩溃后仍能恢复。任何地址都不进脚本、记录、异常或日志。
/// </summary>
public sealed class NicGuard : INicGuard
{
    public const string StateFileName = "nic-guard-state.json";
    internal const int WaitAttempts = 10;
    private static readonly TimeSpan WaitInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ScriptTimeout = TimeSpan.FromSeconds(60);
    private readonly IAdapterProbe probe;
    private readonly ICommandRunner runner;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    public string StatePath { get; }
    public bool HasPendingState => File.Exists(StatePath);

    public NicGuard(string runDirectory, IAdapterProbe probe, ICommandRunner? runner = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        StatePath = Path.Combine(runDirectory, StateFileName);
        this.probe = probe;
        this.runner = runner ?? new CommandRunner();
        this.delay = delay ?? ((span, token) => Task.Delay(span, token));
    }

    internal static string ApplyRefused(string name) =>
        $"未能关闭网卡「{name}」的 IPv6,其公网 IPv6 地址可能被网页读到,已拒绝连接。请点击断开后重试,仍失败请联系管理员。";
    internal static string PatrolRefused(string name) =>
        $"未能关闭网卡「{name}」的 IPv6,隧道保持,但该网卡的公网 IPv6 地址可能被网页读到;请联系管理员。";

    private static bool IsManaged(AdapterInfo adapter) => adapter.Name != KillSwitchPlanner.TunAlias;
    private static bool AnyPublic(IReadOnlyList<AdapterAddress> addresses) =>
        addresses.Any(item => IPAddress.TryParse(item.Address, out var ip) && PublicAddress.IsPublic(ip));

    private IReadOnlyList<AdapterInfo> ReadAdapters() =>
        probe.Snapshot() ?? throw new InvalidOperationException("无法读取网卡地址");

    public string? PublicIpv4Adapter() =>
        ReadAdapters().FirstOrDefault(adapter => IsManaged(adapter) && AnyPublic(adapter.Ipv4))?.Name;

    public async Task ApplyAsync(CancellationToken token)
    {
        var names = ReadAdapters().Where(adapter => IsManaged(adapter) && AnyPublic(adapter.Ipv6)).Select(adapter => adapter.Name).ToArray();
        if (names.Length == 0) return;
        await DisableAsync(names, ApplyRefused, token).ConfigureAwait(false);
    }

    public async Task<NicPatrolReport> PatrolAsync(CancellationToken token)
    {
        var adapters = ReadAdapters();
        var managed = adapters.Where(IsManaged).ToArray();
        var newly = managed.Where(adapter => AnyPublic(adapter.Ipv6)).Select(adapter => adapter.Name).ToArray();
        var publicIpv4 = managed.Where(adapter => AnyPublic(adapter.Ipv4)).Select(adapter => adapter.Name).ToArray();
        if (newly.Length > 0) await DisableAsync(newly, PatrolRefused, token).ConfigureAwait(false);
        return new(newly, publicIpv4);
    }

    // 先把名字并入记录,再执行关闭;之后每秒复核一次,最多十次。
    private async Task DisableAsync(IReadOnlyList<string> names, Func<string, string> refused, CancellationToken token)
    {
        WriteRecord(ReadRecord().Concat(names).Distinct(StringComparer.Ordinal).ToArray());
        var exit = await RunScriptAsync(DisableScript(names), token).ConfigureAwait(false);
        string? offender = null;
        if (exit == 0)
        {
            for (var attempt = 0; attempt < WaitAttempts; attempt++)
            {
                await delay(WaitInterval, token).ConfigureAwait(false);
                var snapshot = probe.Snapshot();
                if (snapshot is null) continue;
                offender = snapshot.FirstOrDefault(adapter => IsManaged(adapter) && AnyPublic(adapter.Ipv6))?.Name;
                if (offender is null) return;
            }
        }
        else offender = probe.Snapshot()?.FirstOrDefault(adapter => names.Contains(adapter.Name) && AnyPublic(adapter.Ipv6))?.Name;
        var name = offender ?? names[0];
        throw new NicGuardException(refused(name)) { AdapterName = name };
    }

    public async Task<string?> RestoreAsync()
    {
        if (!File.Exists(StatePath)) return null;
        string[] recorded;
        try { recorded = ReadRecord(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        { return "网卡 IPv6 的恢复记录无法读取,请重试断开或联系管理员。"; }
        var failed = new List<string>();
        foreach (var name in recorded)
        {
            int exit;
            try { exit = await RunScriptAsync(EnableScript(name), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception) { exit = -1; } // 运行器异常按失败处理,不向外抛。
            if (exit != 0) failed.Add(name);
        }
        try
        {
            if (failed.Count == 0) File.Delete(StatePath);
            else WriteRecord(failed);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { return $"网卡「{string.Join("、", failed.Count == 0 ? recorded : failed)}」的 IPv6 未能恢复,请重试断开或联系管理员。"; }
        return failed.Count == 0 ? null : $"网卡「{string.Join("、", failed)}」的 IPv6 未能恢复,请重试断开或联系管理员。";
    }

    private async Task<int> RunScriptAsync(string script, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(ScriptTimeout);
        try { return (await runner.RunAsync(CreateStartInfo(script), timeout.Token).ConfigureAwait(false)).ExitCode; }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { return -1; }
    }

    internal static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

    internal static string DisableScript(IEnumerable<string> names) =>
        "$failed = 0\n" + string.Concat(names.Select(name =>
            $"try {{ Disable-NetAdapterBinding -Name {Quote(name)} -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop }} catch {{ $failed = 1 }}\n"))
        + "exit $failed";

    // 网卡已不存在算成功。
    internal static string EnableScript(string name) =>
        "$ErrorActionPreference = 'Stop'\ntry {\n" +
        $"  if ($null -eq (Get-NetAdapter -Name {Quote(name)} -ErrorAction SilentlyContinue)) {{ exit 0 }}\n" +
        $"  Enable-NetAdapterBinding -Name {Quote(name)} -ComponentID ms_tcpip6 -Confirm:$false\n" +
        "  exit 0\n} catch { exit 1 }";

    internal static ProcessStartInfo CreateStartInfo(string script)
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script }) start.ArgumentList.Add(arg);
        return start;
    }

    private string[] ReadRecord()
    {
        if (!File.Exists(StatePath)) return [];
        using var json = JsonDocument.Parse(File.ReadAllText(StatePath));
        if (!json.RootElement.TryGetProperty("disabled", out var list) || list.ValueKind != JsonValueKind.Array) return [];
        return list.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()!).ToArray();
    }

    private void WriteRecord(IReadOnlyList<string> names)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
        var temporary = StatePath + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, new { disabled = names },
                    new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
                stream.Flush(true);
            }
            File.Move(temporary, StatePath, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
