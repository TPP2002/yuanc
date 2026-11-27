using System.IO;
using WinClient.App;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ViewModelDiagnosticsTests(UiThreadFixture ui)
{
    [Fact]
    public void ExportWritesFileAndShowsResultOnUpdatePageProperty() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.NowProvider = () => DateTimeOffset.Parse("2026-11-28T01:02:03Z");
        string? receivedPath = null;
        string? receivedText = null;
        model.WriteDiagnosticsFile = (path, text, _) =>
        {
            receivedPath = path;
            receivedText = text;
            return Task.CompletedTask;
        };
        var revealCount = 0;
        string? revealed = null;
        model.RevealFile = path => { revealCount++; revealed = path; return true; };
        var notified = new List<string?>();
        model.PropertyChanged += (_, args) => notified.Add(args.PropertyName);
        var messageBefore = model.Message;
        var path = Path.Combine(Path.GetTempPath(), "diagnostics-export-test.json");
        model.ExportDiagnosticsAsync(path).GetAwaiter().GetResult();
        Assert.Equal(path, receivedPath);
        Assert.False(string.IsNullOrEmpty(receivedText));
        Assert.StartsWith("已导出：", model.DiagnosticsMessage);
        Assert.Contains(path, model.DiagnosticsMessage);
        Assert.Equal(messageBefore, model.Message);
        Assert.Equal(1, revealCount);
        Assert.Equal(path, revealed);
        Assert.Contains(nameof(MainViewModel.DiagnosticsMessage), notified);
    });

    [Fact]
    public void ExportFailureShowsReasonAndDoesNotReveal() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.WriteDiagnosticsFile = (_, _, _) => throw new IOException("disk full");
        var revealCount = 0;
        model.RevealFile = _ => { revealCount++; return true; };
        model.ExportDiagnosticsAsync(Path.Combine(Path.GetTempPath(), "diagnostics-export-test.json"))
            .GetAwaiter().GetResult();
        Assert.Equal("导出失败：文件没能写到所选位置，请换一个位置再试。", model.DiagnosticsMessage);
        Assert.Equal(0, revealCount);
    });

    [Fact]
    public void SuggestedFileNameHasPrefixAndJsonExtension() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        Assert.StartsWith("澳洲出口客户端-诊断-", model.SuggestedDiagnosticsFileName);
        Assert.EndsWith(".json", model.SuggestedDiagnosticsFileName);
    });

    [Fact]
    public void DiagnosticsMessageStartsEmpty() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        Assert.Equal("", model.DiagnosticsMessage);
    });
}
