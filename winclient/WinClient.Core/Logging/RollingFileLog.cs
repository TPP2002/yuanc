using System.Text;

namespace WinClient.Core.Logging;

/// <summary>The caller must redact messages before passing them to this sink.</summary>
public sealed class RollingFileLog : ILog
{
    private readonly object gate = new();
    private readonly string path;
    private readonly long maxBytes;
    private readonly int retainedFiles;

    public RollingFileLog(string path, long maxBytes = 1024 * 1024, int retainedFiles = 3)
    {
        if (maxBytes < 1024) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        if (retainedFiles < 1) throw new ArgumentOutOfRangeException(nameof(retainedFiles));
        this.path = Path.GetFullPath(path);
        this.maxBytes = maxBytes;
        this.retainedFiles = retainedFiles;
    }

    public void Write(string message)
    {
        lock (gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            // A maliciously long kernel line cannot grow one file without a bound.
            var maxChars = (int)Math.Min(16384, maxBytes / 8);
            if (message.Length > maxChars) message = message[..maxChars] + "[已截断]";
            var line = $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}";
            var existing = File.Exists(path) ? new FileInfo(path).Length : 0;
            if (existing + Encoding.UTF8.GetByteCount(line) > maxBytes)
            {
                for (var index = retainedFiles; index >= 1; index--)
                {
                    var source = index == 1 ? path : $"{path}.{index - 1}";
                    if (File.Exists(source)) File.Move(source, $"{path}.{index}", overwrite: true);
                }
            }
            File.AppendAllText(path, line, new UTF8Encoding(false));
        }
    }
}
