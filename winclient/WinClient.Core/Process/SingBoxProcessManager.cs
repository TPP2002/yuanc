using System.Diagnostics;
using System.Text;
using System.Text.Json;
using WinClient.Core.Logging;

namespace WinClient.Core.Process;

public sealed class SingBoxProcessManager : IDisposable
{
    private readonly object gate = new();
    private readonly string executablePath;
    private readonly ISingBoxLauncher launcher;
    private readonly RedactingLog log;
    private ISingBoxProcess? process;
    private long generation;
    private bool disposed;

    public string ConfigPath { get; }
    public event EventHandler<int>? TunnelDown;

    public SingBoxProcessManager(string executablePath, string productName,
        ISingBoxLauncher? launcher = null, ILog? logger = null, string? programDataRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(productName);
        if (productName is "." or ".." || productName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            productName.Contains('/') || productName.Contains('\\'))
            throw new ArgumentException("产品名必须是单个目录名称。", nameof(productName));
        this.executablePath = Path.GetFullPath(executablePath);
        this.launcher = launcher ?? new SingBoxLauncher();
        var root = programDataRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var runPath = Path.Combine(root, productName, "run");
        ConfigPath = Path.Combine(runPath, "config.json");
        log = new RedactingLog(logger ?? new RollingFileLog(Path.Combine(runPath, "sing-box.log")));
    }

    public void Start(JsonElement config)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (config.ValueKind != JsonValueKind.Object)
                throw new ArgumentException("服务器下发的连接配置必须是对象。", nameof(config));
            if (!File.Exists(executablePath))
                throw new FileNotFoundException("未找到连接内核，请联系管理员配置 sing-box.exe 路径。", executablePath);
            StopCore();
            RegisterSecrets(config);
            WriteConfigAtomically(config);
            var currentGeneration = ++generation;
            var startInfo = CreateStartInfo(executablePath, ConfigPath);
            process = launcher.Start(startInfo, log.Write, exitCode =>
            {
                if (Interlocked.Read(ref generation) != currentGeneration) return;
                log.Write($"连接内核已退出，退出状态：{exitCode}。");
                // The controller posts this notification onto its serialized state-machine queue.
                TunnelDown?.Invoke(this, exitCode);
            });
        }
    }

    public static ProcessStartInfo CreateStartInfo(string executablePath, string configPath)
    {
        var info = new ProcessStartInfo
        {
            FileName = Path.GetFullPath(executablePath),
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(executablePath))!,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(Path.GetFullPath(configPath));
        return info;
    }

    public void Stop()
    {
        lock (gate) StopCore();
    }

    private void StopCore()
    {
        Interlocked.Increment(ref generation); // Intentional stops are not crashes.
        if (process is null) return;
        process.Stop();
        process.Dispose();
        process = null;
    }

    private void WriteConfigAtomically(JsonElement config)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        var temporary = ConfigPath + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                var data = Encoding.UTF8.GetBytes(config.GetRawText());
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, ConfigPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private void RegisterSecrets(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in value.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String &&
                    (property.Name.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                     property.Name.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                     property.Name.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                     property.Name.Equals("uuid", StringComparison.OrdinalIgnoreCase)))
                    log.RegisterSecret(property.Value.GetString());
                RegisterSecrets(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) RegisterSecrets(item);
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            StopCore();
            disposed = true;
        }
    }
}
