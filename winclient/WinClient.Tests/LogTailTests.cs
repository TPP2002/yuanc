using System.Text;
using WinClient.Core.Diagnostics;
using Xunit;

namespace WinClient.Tests;

public class LogTailTests
{
    [Fact]
    public void MissingFileIsReportedWithoutThrowing()
    {
        using var directory = new TempDirectory();
        var result = LogTail.Read(directory.Path, "missing.log", 10);
        Assert.True(result.Missing);
        Assert.Equal(0, result.Bytes);
        Assert.False(result.Truncated);
        Assert.Empty(result.Lines);
        Assert.Null(result.Error);
    }

    [Fact]
    public void ReturnsLastLinesAndMarksTruncated()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, "x.log");
        File.WriteAllLines(path, Enumerable.Range(1, 10).Select(index => "line" + index));
        var result = LogTail.Read(directory.Path, "x.log", 3);
        Assert.Equal(new[] { "line8", "line9", "line10" }, result.Lines);
        Assert.True(result.Truncated);
    }

    [Fact]
    public void PrependsRotatedFileWhenCurrentIsShort()
    {
        using var directory = new TempDirectory();
        File.WriteAllLines(Path.Combine(directory.Path, "x.log.1"),
            Enumerable.Range(1, 5).Select(index => "rot" + index));
        File.WriteAllLines(Path.Combine(directory.Path, "x.log"), new[] { "cur1", "cur2" });
        var result = LogTail.Read(directory.Path, "x.log", 4);
        Assert.Equal(new[] { "rot4", "rot5", "cur1", "cur2" }, result.Lines);
        Assert.True(result.Truncated);
    }

    [Fact]
    public void LinesAreRedactedAndOverlongLinesCut()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, "x.log");
        File.WriteAllLines(path, new[] { "访问 8.8.8.8 成功", new string('a', 3000) });
        var result = LogTail.Read(directory.Path, "x.log", 10);
        Assert.Contains(DiagnosticsRedactor.PublicAddressMark, result.Lines[0]);
        Assert.DoesNotContain("8.8.8.8", result.Lines[0]);
        Assert.Equal(LogTail.MaxLineChars + 1, result.Lines[1].Length);
        Assert.EndsWith("…", result.Lines[1]);
    }

    [Fact]
    public void ReadsWhileAnotherHandleIsAppending()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, "x.log");
        using var writer = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        writer.Write(Encoding.UTF8.GetBytes("第一行\n第二行\n"));
        writer.Flush();
        var result = LogTail.Read(directory.Path, "x.log", 10);
        Assert.Equal(new[] { "第一行", "第二行" }, result.Lines);
        Assert.False(result.Missing);
    }

    [Fact]
    public void OversizeFileDropsPartialFirstLine()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, "big.log");
        var line = "LINE-" + new string('x', 995);
        var count = LogTail.MaxReadBytes / (line.Length + 1) + 20;
        File.WriteAllText(path, string.Join("\n", Enumerable.Repeat(line, count)));
        var result = LogTail.Read(directory.Path, "big.log", count);
        Assert.True(result.Truncated);
        Assert.Equal(line, result.Lines[0]);
    }
}
