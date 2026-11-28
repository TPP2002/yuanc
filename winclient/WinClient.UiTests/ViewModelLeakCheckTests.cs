using System.IO;
using System.Text.Json.Nodes;
using WinClient.App;
using WinClient.App.Presentation;
using WinClient.Core.Client;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ViewModelLeakCheckTests(UiThreadFixture ui)
{
    private static ControlSnapshot Snapshot(ConnectionState state) => new(state, "", "", state == ConnectionState.Connected);

    [Fact]
    public void LeakCheckDisabledUntilConnected() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.ApplyPreview(Snapshot(ConnectionState.Disconnected), ServiceAvailability.Ready, connectionUsable: true);
        Assert.False(model.CanLeakCheck);
        Assert.False(model.LeakCheckCommand.CanExecute(null));
        Assert.Equal(MainViewModel.LeakCheckNeedsConnection, model.LeakCheckDisabledReason);
        model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
        Assert.True(model.CanLeakCheck);
        Assert.True(model.LeakCheckCommand.CanExecute(null));
        Assert.Equal("", model.LeakCheckDisabledReason);
        model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Unavailable, connectionUsable: true);
        Assert.False(model.CanLeakCheck);
        Assert.Equal(model.ConnectionDisabledReason, model.LeakCheckDisabledReason);
    });

    [Fact]
    public async Task LeakCheckRunsWithoutOccupyingConnectButton()
    {
        var gate = new TaskCompletionSource<ControlResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        MainViewModel model = null!;
        var running = Task.CompletedTask;
        ui.Invoke(() =>
        {
            model = new MainViewModel(() => null, () => null);
            model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
            model.SendLeakCheck = _ => gate.Task;
            running = model.RunLeakCheckAsync();
            Assert.True(model.IsLeakCheckRunning);
            Assert.False(model.IsBusy);
            Assert.True(model.CanUseConnection);
            Assert.False(model.CanLeakCheck);
            Assert.Equal("", model.LeakCheckMessage);
            Assert.Equal("", model.LeakCheckDisabledReason);
        });
        gate.SetResult(new ControlResponse(1, true, LeakCheck: "未发现可疑流量。"));
        await running.WaitAsync(TimeSpan.FromSeconds(10));
        ui.Invoke(() =>
        {
            Assert.False(model.IsLeakCheckRunning);
            Assert.Equal("未发现可疑流量。", model.LeakCheckMessage);
            Assert.True(model.CanLeakCheck);
            model.Dispose();
        });
    }

    [Fact]
    public async Task LeakCheckInterruptedByDisconnectDiscardsResult()
    {
        var gate = new TaskCompletionSource<ControlResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        MainViewModel model = null!;
        var running = Task.CompletedTask;
        ui.Invoke(() =>
        {
            model = new MainViewModel(() => null, () => null);
            model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
            model.SendLeakCheck = _ => gate.Task;
            running = model.RunLeakCheckAsync();
            Assert.True(model.IsLeakCheckRunning);
            model.ApplyPreview(Snapshot(ConnectionState.Disconnected), ServiceAvailability.Ready, connectionUsable: true);
            model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
            Assert.True(model.IsLeakCheckRunning);
        });
        gate.SetResult(new ControlResponse(1, true, LeakCheck: "未发现可疑流量。"));
        await running.WaitAsync(TimeSpan.FromSeconds(10));
        string? written = null;
        ui.Invoke(() =>
        {
            Assert.False(model.IsLeakCheckRunning);
            Assert.Equal(MainViewModel.LeakCheckInterruptedMessage, model.LeakCheckMessage);
            model.WriteDiagnosticsFile = (_, text, _) => { written = text; return Task.CompletedTask; };
            model.RevealFile = _ => true;
            model.ExportDiagnosticsAsync(Path.Combine(Path.GetTempPath(), "leak-check-interrupted.json")).GetAwaiter().GetResult();
            model.Dispose();
        });
        Assert.NotNull(written);
        Assert.Null(JsonNode.Parse(written!)!["ui"]!["leak_check"]);
    }

    [Fact]
    public void LeakCheckFailureShowsFixedMessage() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
        model.SendLeakCheck = _ => throw new IOException("抓包没有做完");
        model.RunLeakCheckAsync().GetAwaiter().GetResult();
        Assert.Equal(MainViewModel.LeakCheckFailedMessage, model.LeakCheckMessage);
        Assert.False(model.IsLeakCheckRunning);
    });

    [Fact]
    public void LeakCheckErrorResponseShowsServerError() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
        model.SendLeakCheck = _ => Task.FromResult(new ControlResponse(1, false, ControlServer.LeakCheckBusyError));
        model.RunLeakCheckAsync().GetAwaiter().GetResult();
        Assert.Equal(ControlServer.LeakCheckBusyError, model.LeakCheckMessage);
        Assert.False(model.IsLeakCheckRunning);
    });

    [Fact]
    public void ExportIncludesLastLeakCheckRedacted() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.ApplyPreview(Snapshot(ConnectionState.Connected), ServiceAvailability.Ready, connectionUsable: true);
        model.SendLeakCheck = _ => Task.FromResult(new ControlResponse(1, true, LeakCheck: "发现可疑流量：1 条，共 3 个包。\nTCP 8.8.8.8:443 chrome.exe ×3"));
        model.RunLeakCheckAsync().GetAwaiter().GetResult();
        string? written = null;
        model.WriteDiagnosticsFile = (_, text, _) => { written = text; return Task.CompletedTask; };
        model.RevealFile = _ => true;
        model.ExportDiagnosticsAsync(Path.Combine(Path.GetTempPath(), "leak-check-export-test.json")).GetAwaiter().GetResult();
        Assert.NotNull(written);
        var leak = JsonNode.Parse(written!)!["ui"]!["leak_check"]!.GetValue<string>();
        Assert.Contains("[公网地址]:443", leak);
        Assert.Contains("chrome.exe", leak);
        Assert.DoesNotContain("8.8.8.8", written);
    });

    [Fact]
    public void ExportLeakCheckIsNullBeforeAnyRun() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        string? written = null;
        model.WriteDiagnosticsFile = (_, text, _) => { written = text; return Task.CompletedTask; };
        model.RevealFile = _ => true;
        model.ExportDiagnosticsAsync(Path.Combine(Path.GetTempPath(), "leak-check-none.json")).GetAwaiter().GetResult();
        Assert.NotNull(written);
        Assert.Null(JsonNode.Parse(written!)!["ui"]!["leak_check"]);
    });
}
