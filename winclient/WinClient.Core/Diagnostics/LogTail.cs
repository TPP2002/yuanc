using System.Text;

namespace WinClient.Core.Diagnostics;

public sealed record LogTailResult(string Name, bool Missing, long Bytes, bool Truncated, IReadOnlyList<string> Lines, string? Error = null);

public static class LogTail
{
    public const int MaxLineChars = 2000;
    public const int MaxReadBytes = 512 * 1024;

    public static LogTailResult Read(string directory, string name, int maxLines)
    {
        var current = Path.Combine(directory, name);
        var rotated = current + ".1";
        var currentExists = File.Exists(current);
        var rotatedExists = File.Exists(rotated);
        if (!currentExists && !rotatedExists) return new(name, true, 0, false, []);
        try
        {
            var bytes = currentExists ? new FileInfo(current).Length : 0;
            var truncated = false;
            var lines = currentExists ? ReadLines(current, ref truncated) : [];
            if (maxLines <= 0)
            {
                var any = lines.Count > 0;
                if (!any && rotatedExists) any = ReadLines(rotated, ref truncated).Count > 0;
                return new(name, false, bytes, truncated || any, []);
            }
            if (lines.Count < maxLines && rotatedExists)
            {
                var older = ReadLines(rotated, ref truncated);
                var needed = maxLines - lines.Count;
                if (older.Count > needed)
                {
                    older.RemoveRange(0, older.Count - needed);
                    truncated = true;
                }
                lines.InsertRange(0, older);
            }
            if (lines.Count > maxLines)
            {
                lines.RemoveRange(0, lines.Count - maxLines);
                truncated = true;
            }
            var result = new List<string>(lines.Count);
            foreach (var line in lines)
            {
                var redacted = DiagnosticsRedactor.Redact(line);
                result.Add(redacted.Length > MaxLineChars ? redacted[..MaxLineChars] + "…" : redacted);
            }
            return new(name, false, bytes, truncated, result);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(name, false, 0, false, [], "读取失败");
        }
    }

    private static List<string> ReadLines(string path, ref bool truncated)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var start = Math.Max(0, stream.Length - MaxReadBytes);
        if (start > 0) truncated = true;
        stream.Seek(start, SeekOrigin.Begin);
        var buffer = new byte[(int)(stream.Length - start)];
        var read = 0;
        while (read < buffer.Length)
        {
            var count = stream.Read(buffer, read, buffer.Length - read);
            if (count == 0) break;
            read += count;
        }
        var text = Encoding.UTF8.GetString(buffer, 0, read);
        if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];
        var lines = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.EndsWith('\r') ? raw[..^1] : raw;
            if (line.Length > 0) lines.Add(line);
        }
        // 从中间开始读时，第一条是截断的半行，丢掉。
        if (start > 0 && lines.Count > 0) lines.RemoveAt(0);
        return lines;
    }
}
