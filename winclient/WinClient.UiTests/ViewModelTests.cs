using System.IO;
using System.ServiceProcess;
using WinClient.App;
using WinClient.App.Presentation;
using WinClient.Core.Hosting;
using WinClient.Core.Ipc;
using WinClient.Core.Client;
using WinClient.Core.State;
using WinClient.Core.Update;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class ViewModelTests(UiThreadFixture ui)
{
    [Fact]
    public void 更新提示超过一秒才出现() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var now = DateTimeOffset.Parse("2026-10-23T10:00:00Z");
        model.NowProvider = () => now;
        var notified = new List<string?>();
        model.PropertyChanged += (_, args) => notified.Add(args.PropertyName);
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false)
            { Update = new UpdateStatus("downloading", Message: "正在下载 1.3.1…") }, ServiceAvailability.Ready);
        Assert.True(model.IsUpdateInProgress);
        Assert.False(model.IsUpdateIndicatorVisible);
        now += TimeSpan.FromMilliseconds(999);
        model.RefreshUpdateIndicator();
        Assert.False(model.IsUpdateIndicatorVisible);
        Assert.DoesNotContain(nameof(MainViewModel.IsUpdateIndicatorVisible), notified);
        now += TimeSpan.FromMilliseconds(1);
        model.RefreshUpdateIndicator();
        Assert.True(model.IsUpdateIndicatorVisible);
        Assert.Contains(nameof(MainViewModel.IsUpdateIndicatorVisible), notified);
    });

    [Fact]
    public void 更新结束立即隐藏且再开始重新计时() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var now = DateTimeOffset.Parse("2026-10-23T10:00:00Z");
        model.NowProvider = () => now;
        var active = new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false)
            { Update = new UpdateStatus("downloading", Message: "正在下载 1.3.1…") };
        model.ApplyPreview(active, ServiceAvailability.Ready);
        now += TimeSpan.FromSeconds(1);
        model.RefreshUpdateIndicator();
        Assert.True(model.IsUpdateIndicatorVisible);
        model.ApplyPreview(active with { Update = new UpdateStatus("idle") }, ServiceAvailability.Ready);
        Assert.False(model.IsUpdateIndicatorVisible);
        model.ApplyPreview(active, ServiceAvailability.Ready);
        Assert.False(model.IsUpdateIndicatorVisible);
        now += TimeSpan.FromSeconds(1);
        model.RefreshUpdateIndicator();
        Assert.True(model.IsUpdateIndicatorVisible);
    });

    [Fact]
    public void 预览声明连接可用时按钮启用且可用性仍受后台状态约束() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var snapshot = new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false);
        model.ApplyPreview(snapshot, ServiceAvailability.Ready, connectionUsable: true);
        Assert.True(model.CanUseConnection);
        Assert.True(model.CheckUpdateCommand.CanExecute(null));
        Assert.True(model.CanRestoreEnvironment);
        Assert.Equal("", model.ConnectionDisabledReason);
        model.ApplyPreview(snapshot, ServiceAvailability.Unavailable, connectionUsable: true);
        Assert.False(model.CanUseConnection);
        Assert.Contains("未就绪", model.ConnectionDisabledReason);
        model.ApplyPreview(snapshot, ServiceAvailability.Ready);
        Assert.False(model.CanUseConnection);
    });

    [Fact]
    public void 浏览器提醒随快照更新且没有后台连接不能继续() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var notified = new List<string?>();
        model.PropertyChanged += (_, args) => notified.Add(args.PropertyName);
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接",
            "Chrome 正在运行:" + ClientController.BrowserWarningMarker, false), ServiceAvailability.Ready);
        Assert.True(model.BrowserWarningShown);
        Assert.Contains(nameof(MainViewModel.BrowserWarningShown), notified);
        Assert.NotNull(model.ContinueAnywayCommand);
        Assert.False(model.ContinueAnywayCommand.CanExecute(null));
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", "普通消息", false), ServiceAvailability.Ready);
        Assert.False(model.BrowserWarningShown);
        Assert.False(model.ContinueAnywayCommand.CanExecute(null));
    });

    [Fact]
    public void 强制恢复在连接保护或后台不可用时禁用() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        Assert.NotNull(model.RestoreEnvironmentCommand);
        foreach (var snapshot in new[] {
            new ControlSnapshot(ConnectionState.Connected, "已连接", "", false),
            new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", true),
            new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false) })
        {
            model.ApplyPreview(snapshot, ServiceAvailability.Ready);
            Assert.False(model.RestoreEnvironmentCommand.CanExecute(null));
            Assert.False(model.CanRestoreEnvironment);
        }
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false), ServiceAvailability.Unavailable);
        Assert.False(model.RestoreEnvironmentCommand.CanExecute(null));
        Assert.False(model.CanRestoreEnvironment);
    });

    [Fact]
    public void 浏览器复核无需后台且保留主消息() => ui.Invoke(() =>
    {
        string? received = null;
        using var model = new MainViewModel(() => null, () => null, null,
            html => { received = html; return @"C:\fake\verify.html"; });
        model.ApplyPreview(new ControlSnapshot(ConnectionState.Disconnected, "未连接", "", false)
            { RoutingMode = "apps", EnvironmentEnabled = false }, ServiceAvailability.Unavailable);
        var message = model.Message;
        Assert.True(model.OpenVerifyPageCommand.CanExecute(null));
        model.OpenVerifyPageAsync().GetAwaiter().GetResult();
        Assert.Contains("data-mode=\"apps\"", received);
        Assert.Contains("data-env=\"off\"", received);
        Assert.Contains(@"C:\fake\verify.html", model.VerifyPageMessage);
        Assert.Equal(message, model.Message);
        using var failed = new MainViewModel(() => null, () => null, null, _ => null);
        failed.OpenVerifyPageAsync().GetAwaiter().GetResult();
        Assert.Contains("未完成", failed.VerifyPageMessage);
    });

    [Fact]
    public void 专用浏览器无需后台且不修改主消息() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null,
            (_, _) => Task.FromResult<string?>("{\"created\":[\"Chrome\"],\"missing\":[\"Edge\"],\"kept\":[]}"));
        var message = model.Message;
        Assert.True(model.CreateBrowserProfileCommand.CanExecute(null));
        model.CreateBrowserProfileAsync().GetAwaiter().GetResult();
        Assert.Contains("澳洲专用 Chrome", model.BrowserProfileMessage);
        Assert.Contains("未找到 Edge", model.BrowserProfileMessage);
        Assert.Equal(message, model.Message);
        using var failed = new MainViewModel(() => null, () => null, (_, _) => Task.FromResult<string?>(null));
        failed.CreateBrowserProfileAsync().GetAwaiter().GetResult();
        Assert.Contains("未完成", failed.BrowserProfileMessage);
    });

    [Theory]
    [InlineData("通过", Tone.Ok, Glyph.Check, false)]
    [InlineData("未通过", Tone.Bad, Glyph.X, false)]
    [InlineData("跳过", Tone.N, Glyph.Ring, true)]
    [InlineData("无法核验", Tone.Warn, Glyph.Ask, false)]
    public void 自检明细解析并映射四种结果(string result, Tone tone, Glyph glyph, bool dim) => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        model.ApplySelfCheckJson(System.Text.Json.JsonSerializer.Serialize(new
        {
            checked_at = "2026-10-22T14:32:00+08:00", summary = "测试汇总",
            items = new[] { new { id = "timezone", name = "系统时区", result, detail = "检查明细" } }
        }));
        var item = Assert.Single(model.SelfCheckItems);
        Assert.Equal(1, item.Index); Assert.Equal("系统时区", item.Name); Assert.Equal("检查明细", item.Detail);
        Assert.Equal(new TileSpec(tone, glyph, Flow.None, Dim: dim), item.Tile);
        Assert.Equal("测试汇总", model.SelfCheckSummary); Assert.Equal("2026-10-22T14:32:00+08:00", model.SelfCheckCheckedAtText);
        model.ApplySelfCheckJson("{}"); Assert.Empty(model.SelfCheckItems);
        Assert.Equal("", model.SelfCheckSummary);
    });
    [Fact]
    public void 预览不建立连接且保留消息和版本() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => throw new Exception("不应弹出文件选择"), () => throw new Exception("不应选择程序"));
        var snapshot = new ControlSnapshot(ConnectionState.NeedsLogin, "需要重新登录", "会话已到期", true)
        { ServiceVersion = "1.3.0", Mode = "分发模式", Update = new UpdateStatus("checking", Message: "正在检查更新") };
        model.ApplyPreview(snapshot, ServiceAvailability.Ready);
        Assert.Equal("断开", model.ConnectLabel); Assert.True(model.Hero.ShowGoToAccount); Assert.False(model.CanUseConnection);
        Assert.Equal("版本 1.3.0", model.ServiceVersionText); Assert.Equal("分发模式", model.ModeText);
        Assert.Equal("会话已到期 后台已更新到 1.3.0，下次打开界面将使用新版", model.Message);
        Assert.True(model.IsUpdateInProgress);
        model.GoToAccountCommand.Execute(null); Assert.Equal(PageKind.Account, model.CurrentPage);
    });

    [Fact]
    public void 首次安装成功后界面交接给已安装的程序() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        ServiceControllerStatus? status = null;
        var decision = new UiHandoverDecision(UiHandoverKind.Reinstall);
        var target = Path.GetFullPath("Program Files/YuanC/app/0.1.0/YuanC-Client.exe");
        var elevated = "";
        var handed = new List<string>();
        model.ServiceStatusProvider = () => status;
        model.DecideHandoverAsync = _ => Task.FromResult(decision);
        model.ElevateAsync = action =>
        {
            elevated = action;
            status = ServiceControllerStatus.Running;
            decision = new UiHandoverDecision(UiHandoverKind.Handover, target);
            return Task.FromResult(true);
        };
        model.Handover = path => { handed.Add(path); return true; };
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        Assert.Equal("安装后台服务", model.Hero.PrimaryLabel);
        model.ConnectCommand.Execute(null);
        Assert.Equal("--install", elevated);
        Assert.Single(handed);
        Assert.Equal(target, handed[0]);
        Assert.False(model.CanUseConnection);
    });

    [Fact]
    public void 界面在安装目录外且已装同一份时直接交接() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var target = Path.GetFullPath("Program Files/YuanC/app/0.1.0/YuanC-Client.exe");
        var handed = new List<string>();
        var elevated = false;
        model.ServiceStatusProvider = () => ServiceControllerStatus.Running;
        model.DecideHandoverAsync = _ => Task.FromResult(new UiHandoverDecision(UiHandoverKind.Handover, target));
        model.ElevateAsync = _ => { elevated = true; return Task.FromResult(true); };
        model.Handover = path => { handed.Add(path); return true; };
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        Assert.Single(handed);
        Assert.Equal(target, handed[0]);
        Assert.False(elevated);
        Assert.False(model.CanUseConnection);
        Assert.False(model.ImportPairingCommand.CanExecute(null));
    });

    [Fact]
    public void 交接失败时停在可重试的提示() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var target = Path.GetFullPath("Program Files/YuanC/app/0.1.0/YuanC-Client.exe");
        model.ServiceStatusProvider = () => ServiceControllerStatus.Running;
        model.DecideHandoverAsync = _ => Task.FromResult(new UiHandoverDecision(UiHandoverKind.Handover, target));
        model.ElevateAsync = _ => Task.FromResult(true);
        model.Handover = _ => false;
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        Assert.Equal("无法打开已安装的客户端", model.Status);
        Assert.Equal("重新连接后台服务", model.Hero.PrimaryLabel);
        Assert.False(model.CanUseConnection);
        model.Handover = null;
        var again = model.InitializeAsync();
        Assert.True(again.IsCompletedSuccessfully);
        Assert.Equal("无法打开已安装的客户端", model.Status);
        Assert.Equal("重新连接后台服务", model.Hero.PrimaryLabel);
    });

    [Fact]
    public void 这个文件比已装的新时先提示安装再交接() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var target = Path.GetFullPath("Program Files/YuanC/app/0.1.0/YuanC-Client.exe");
        var target2 = Path.GetFullPath("Program Files/YuanC/app/0.1.1/YuanC-Client.exe");
        var decision = new UiHandoverDecision(UiHandoverKind.Upgrade, target, "0.1.0");
        var elevated = "";
        var handed = new List<string>();
        model.ServiceStatusProvider = () => ServiceControllerStatus.Running;
        model.DecideHandoverAsync = _ => Task.FromResult(decision);
        model.ElevateAsync = action =>
        {
            elevated = action;
            decision = new UiHandoverDecision(UiHandoverKind.Handover, target2);
            return Task.FromResult(true);
        };
        model.Handover = path => { handed.Add(path); return true; };
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        Assert.Equal("可安装新版本", model.Hero.Title);
        Assert.Equal("安装这个版本", model.Hero.PrimaryLabel);
        Assert.Equal("后台服务 · 可安装新版本", model.ServiceStateText);
        Assert.Contains("已装 0.1.0", model.Message);
        Assert.EndsWith("点「安装这个版本」换成新版，需管理员确认一次。", model.Message);
        Assert.False(model.CanUseConnection);
        Assert.Empty(handed);
        model.ConnectCommand.Execute(null);
        Assert.Equal("--install", elevated);
        Assert.Single(handed);
        Assert.Equal(target2, handed[0]);
    });

    [Fact]
    public void 安装没完成时不交接() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var handed = new List<string>();
        model.ServiceStatusProvider = () => null;
        model.DecideHandoverAsync = _ => Task.FromResult(new UiHandoverDecision(UiHandoverKind.Reinstall));
        model.ElevateAsync = _ => Task.FromResult(false);
        model.Handover = path => { handed.Add(path); return true; };
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        model.ConnectCommand.Execute(null);
        Assert.Equal("操作未完成，请重试或联系管理员。", model.Message);
        Assert.Empty(handed);
        Assert.Equal("安装后台服务", model.Hero.PrimaryLabel);
    });

    [Fact]
    public void 服务登记的程序不可用时回到安装() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var handed = new List<string>();
        model.ServiceStatusProvider = () => ServiceControllerStatus.Running;
        model.DecideHandoverAsync = _ => Task.FromResult(new UiHandoverDecision(UiHandoverKind.Reinstall));
        model.ElevateAsync = _ => Task.FromResult(true);
        model.Handover = path => { handed.Add(path); return true; };
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        Assert.Equal("安装后台服务", model.Hero.PrimaryLabel);
        Assert.Empty(handed);
    });

    [Fact]
    public void 界面已在安装目录时照旧判断服务状态() => ui.Invoke(() =>
    {
        using var model = new MainViewModel(() => null, () => null);
        var handed = new List<string>();
        model.ServiceStatusProvider = () => ServiceControllerStatus.Stopped;
        model.DecideHandoverAsync = _ => Task.FromResult(new UiHandoverDecision(UiHandoverKind.Stay));
        model.ElevateAsync = _ => Task.FromResult(true);
        model.Handover = path => { handed.Add(path); return true; };
        var init = model.InitializeAsync();
        Assert.True(init.IsCompletedSuccessfully);
        Assert.Equal("修复后台服务", model.Hero.PrimaryLabel);
        Assert.Empty(handed);
    });
}
