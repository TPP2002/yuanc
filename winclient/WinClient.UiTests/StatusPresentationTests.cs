using WinClient.App.Presentation;
using WinClient.Core.Ipc;
using WinClient.Core.State;
using Xunit;

namespace WinClient.UiTests;

public class StatusPresentationTests
{
    private static ControlSnapshot Snapshot(ConnectionState state = ConnectionState.Disconnected) => new(state, "后台服务连接已中断", "原始消息", false);
    private static HeroPresentation Build(ControlSnapshot snapshot, bool disconnect = false) => StatusPresentation.Build(snapshot, ServiceAvailability.Ready, disconnect);

    [Theory]
    [InlineData(ServiceAvailability.NeedInstall, "需安装后台服务", "安装后台服务", Tone.N, Glyph.Plug, TrayIcon.N)]
    [InlineData(ServiceAvailability.NeedRepair, "后台服务未运行", "修复后台服务", Tone.Warn, Glyph.Bang, TrayIcon.Warn)]
    [InlineData(ServiceAvailability.Unavailable, "后台服务连接已中断", "重新连接后台服务", Tone.Bad, Glyph.X, TrayIcon.Bad)]
    public void 服务优先于连接状态(ServiceAvailability availability, string title, string primary, Tone tone, Glyph glyph, TrayIcon tray)
    {
        var hero = StatusPresentation.Build(Snapshot(ConnectionState.Connected), availability, true);
        Assert.Equal(title, hero.Title); Assert.Equal(primary, hero.PrimaryLabel);
        Assert.Equal(new TileSpec(tone, glyph, Flow.None), hero.Tile);
        Assert.Equal(tray, hero.Tray); Assert.Equal("正在处理", hero.BusyLabel);
        if (availability == ServiceAvailability.Unavailable) { Assert.Equal("原始消息", hero.Subtitle); Assert.Equal(Tone.Bad, hero.SubtitleTone); }
    }

    [Theory]
    [InlineData("global", "点「连接」后,所有程序都从澳洲出口上网")]
    [InlineData("apps", "点「连接」后,指定的 2 个程序从澳洲出口上网")]
    public void 未连接说明范围(string mode, string subtitle)
    {
        var hero = Build(Snapshot() with { RoutingMode = mode, RoutingApps = ["a.exe", "b.exe"] });
        Assert.Equal("未连接", hero.Title); Assert.Equal(subtitle, hero.Subtitle);
        Assert.Equal("连接", hero.PrimaryLabel); Assert.Equal("正在连接", hero.BusyLabel);
        Assert.Equal(new TileSpec(Tone.N, Glyph.Ring, Flow.None), hero.Tile); Assert.Equal(TrayIcon.N, hero.Tray);
    }

    [Theory]
    [InlineData(ConnectionState.Connecting, "正在连接", Tone.Info, Glyph.Bars, Flow.Forward, TrayIcon.Info)]
    [InlineData(ConnectionState.Reconnecting, "正在重连", Tone.Info, Glyph.Spin, Flow.Reverse, TrayIcon.Info)]
    [InlineData(ConnectionState.NeedsLogin, "需要重新登录", Tone.Warn, Glyph.Ask, Flow.Fast, TrayIcon.Warn)]
    [InlineData(ConnectionState.NeedsManual, "需要处理", Tone.Bad, Glyph.Bang, Flow.None, TrayIcon.Bad)]
    public void 连接状态保持原始消息(ConnectionState state, string title, Tone tone, Glyph glyph, Flow flow, TrayIcon tray)
    {
        var hero = Build(Snapshot(state), true);
        Assert.Equal(title, hero.Title); Assert.Equal("原始消息", hero.Subtitle);
        Assert.Equal(new TileSpec(tone, glyph, flow), hero.Tile); Assert.Equal(tray, hero.Tray);
        Assert.Equal("断开", hero.PrimaryLabel); Assert.Equal("正在断开", hero.BusyLabel);
        Assert.Equal(state == ConnectionState.NeedsLogin, hero.ShowGoToAccount);
        Assert.Equal("澳洲出口客户端 · " + title, hero.TrayText); Assert.True(hero.TrayText.Length <= 63);
    }

    [Theory]
    [InlineData(ConnectionState.NeedsLogin)]
    [InlineData(ConnectionState.NeedsManual)]
    public void 等待人工且无保护时可连接(ConnectionState state) => Assert.Equal("连接", Build(Snapshot(state)).PrimaryLabel);

    [Theory]
    [InlineData("", Tone.N, TrayIcon.Ok)]
    [InlineData("正常", Tone.N, TrayIcon.Ok)]
    [InlineData("断网保护未能重新套用:请开启防火墙", Tone.Bad, TrayIcon.Warn)]
    [InlineData("系统防火墙已被关闭或被策略覆盖,断网保护可能失效", Tone.Bad, TrayIcon.Warn)]
    [InlineData("巡检失败,下一轮重试", Tone.Warn, TrayIcon.Warn)]
    public void 已连接保留隧道并显示保护警告(string guard, Tone subtitleTone, TrayIcon tray)
    {
        var hero = Build(Snapshot(ConnectionState.Connected) with { GuardStatus = guard, ExitStatus = "已核验", ExitIp = "203.0.113.9" }, true);
        Assert.Equal("已连接", hero.Title); Assert.Equal(new TileSpec(Tone.Ok, Glyph.Check, Flow.None, true), hero.Tile);
        Assert.Equal(tray, hero.Tray); Assert.Equal(subtitleTone, hero.SubtitleTone);
        Assert.Equal(guard is "" or "正常" ? "出口 203.0.113.9 · 与澳洲节点一致" : guard, hero.Subtitle);
        Assert.Equal("断开", hero.PrimaryLabel);
    }

    [Theory]
    [InlineData("未检测", Tone.N, Glyph.Ring, "待检测", "")]
    [InlineData("核验中", Tone.Info, Glyph.Dots, "核验中…", "")]
    [InlineData("已核验", Tone.Ok, Glyph.Check, "203.0.113.9 · 与澳洲节点一致", "5 分钟后复查")]
    [InlineData("已核验(后台服务出口)", Tone.Ok, Glyph.Check, "203.0.113.9 · 与澳洲节点一致(仅证明后台服务出口)", "")]
    [InlineData("不一致", Tone.Bad, Glyph.Bang, "203.0.113.9 · 与澳洲节点不一致,请联系管理员", "")]
    [InlineData("不一致(后台服务出口)", Tone.Bad, Glyph.Bang, "203.0.113.9 · 与澳洲节点不一致,请联系管理员", "")]
    [InlineData("无法核验", Tone.Warn, Glyph.Ask, "无法核验(隧道内暂无回应)", "")]
    public void 出口各分支(string status, Tone tone, Glyph glyph, string text, string right)
    {
        var row = Build(Snapshot() with { ExitStatus = status, ExitIp = "203.0.113.9" }).Rows[0];
        Assert.Equal("出口 IP", row.Label); Assert.Equal(tone, row.Tile.Tone); Assert.Equal(glyph, row.Tile.Glyph);
        Assert.Equal(text, row.Text); Assert.Equal(right, row.Right);
    }

    [Theory]
    [InlineData(false, "", "未启用,连接时自动开启", Tone.N, Glyph.Ring)]
    [InlineData(true, "", "已开启,60 秒后首次巡检", Tone.Ok, Glyph.Check)]
    [InlineData(true, "正常", "正常,每 60 秒巡检一次", Tone.Ok, Glyph.Check)]
    [InlineData(true, "巡检失败,下一轮重试", "巡检失败,下一轮重试", Tone.Warn, Glyph.Ask)]
    [InlineData(true, "断网保护未能重新套用:测试", "断网保护未能重新套用:测试", Tone.Bad, Glyph.Bang)]
    public void 保护各分支(bool active, string guard, string text, Tone tone, Glyph glyph)
    {
        var row = Build(Snapshot() with { ProtectionActive = active, GuardStatus = guard }).Rows[1];
        Assert.Equal(text, row.Text); Assert.Equal(tone, row.Tile.Tone); Assert.Equal(glyph, row.Tile.Glyph);
    }

    [Fact]
    public void 到期仍保持保护() => Assert.Equal("保持中(到期后不撤)", Build(Snapshot(ConnectionState.NeedsLogin) with { ProtectionActive = true }).Rows[1].Text);

    [Theory]
    [InlineData("核验中", "正在核验出口…", Tone.N)]
    [InlineData("无法核验", "出口无法核验(隧道内暂无回应)", Tone.Warn)]
    [InlineData("不一致", "出口 203.0.113.9 与澳洲节点不一致,请联系管理员", Tone.Bad)]
    [InlineData("不一致(后台服务出口)", "出口 203.0.113.9 与澳洲节点不一致,请联系管理员", Tone.Bad)]
    public void 已连接出口摘要(string exit, string subtitle, Tone tone)
    {
        var hero = Build(Snapshot(ConnectionState.Connected) with { ExitStatus = exit, ExitIp = "203.0.113.9" }, true);
        Assert.Equal(subtitle, hero.Subtitle); Assert.Equal(tone, hero.SubtitleTone); Assert.Equal(TrayIcon.Ok, hero.Tray);
    }

    [Fact]
    public void 托盘文案截断但界面标题不截断()
    {
        var status = new string('长', 100);
        var hero = StatusPresentation.Build(Snapshot() with { Status = status }, ServiceAvailability.Unavailable, false);
        Assert.Equal(status, hero.Title); Assert.Equal(63, hero.TrayText.Length);
        Assert.StartsWith("澳洲出口客户端 · ", hero.TrayText);
    }

    [Theory]
    [InlineData("未检测", Tone.N, Glyph.Ring)]
    [InlineData("检测中", Tone.Info, Glyph.Dots)]
    [InlineData("8 项通过", Tone.Ok, Glyph.Check)]
    [InlineData("7 项通过,1 项未能检查", Tone.Warn, Glyph.Ask)]
    [InlineData("1 项未通过:时区", Tone.Bad, Glyph.X)]
    public void 自检各分支(string status, Tone tone, Glyph glyph)
    {
        var row = Build(Snapshot() with { SelfCheckStatus = status }).Rows[2];
        Assert.Equal(status, row.Text); Assert.Equal(tone, row.Tile.Tone); Assert.Equal(glyph, row.Tile.Glyph);
        Assert.Equal("看明细在「环境一致」", row.Right);
    }

    [Theory]
    [InlineData("未应用", true, Tone.N, Glyph.Ring, false, "未应用")]
    [InlineData("未启用", false, Tone.N, Glyph.Ring, true, "未启用")]
    [InlineData("已切换到澳洲时区与浏览器策略", true, Tone.Ok, Glyph.Check, false, "已应用:澳洲东部时区、Chrome 与 Edge 首选语言")]
    [InlineData("设置失败:时区", true, Tone.Bad, Glyph.Bang, false, "设置失败:时区")]
    [InlineData("恢复失败:时区", true, Tone.Bad, Glyph.Bang, false, "恢复失败:时区")]
    public void 环境各分支(string status, bool enabled, Tone tone, Glyph glyph, bool dim, string text)
    {
        var row = Build(Snapshot() with { EnvironmentStatus = status, EnvironmentEnabled = enabled }).Rows[3];
        Assert.Equal(new TileSpec(tone, glyph, Flow.None, Dim: dim), row.Tile); Assert.Equal(text, row.Text);
    }
}
