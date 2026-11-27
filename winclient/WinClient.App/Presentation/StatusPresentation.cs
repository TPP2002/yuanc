using WinClient.Core.Client;
using WinClient.Core.Ipc;
using WinClient.Core.State;

namespace WinClient.App.Presentation;

public enum Tone { N, Info, Warn, Ok, Bad }
public enum Glyph { Ring, Dots, Bars, Check, Spin, Ask, Bang, X, Plug }
public enum Flow { None, Forward, Reverse, Fast }
public enum TrayIcon { N, Info, Ok, Warn, Bad }
public enum ServiceAvailability { Unavailable, NeedInstall, NeedRepair, Ready, NeedUpgrade }
public enum PageKind { Connect, Routing, Environment, Account, Update }
public sealed record TileSpec(Tone Tone, Glyph Glyph, Flow Flow, bool Filled = false, bool Dim = false);
public sealed record StatusRow(string Label, TileSpec Tile, string Text, Tone TextTone, string Right = "");
public sealed record HeroPresentation(TileSpec Tile, string Title, string Subtitle, Tone SubtitleTone,
    string PrimaryLabel, string BusyLabel, bool ShowGoToAccount, TrayIcon Tray, string TrayText, IReadOnlyList<StatusRow> Rows);

/// <summary>设计正本第 4 节的显示映射，不执行命令，也不依赖界面框架。</summary>
public static class StatusPresentation
{
    public static HeroPresentation Build(ControlSnapshot snapshot, ServiceAvailability availability, bool shouldDisconnect, bool? testBuild = null)
    {
        var isTestBuild = testBuild ?? BuildInfo.TestBuild;
        var rows = new[] { Exit(snapshot), isTestBuild ? TestBuildGuard() : Guard(snapshot), SelfCheck(snapshot), Environment(snapshot) };
        var primary = shouldDisconnect ? "断开" : "连接";
        var title = "未连接";
        var subtitle = snapshot.Message;
        var subtitleTone = Tone.N;
        var tile = new TileSpec(Tone.N, Glyph.Ring, Flow.None);
        var tray = TrayIcon.N;
        var account = false;
        switch (availability)
        {
            case ServiceAvailability.NeedInstall:
                tile = new(Tone.N, Glyph.Plug, Flow.None); title = "需安装后台服务";
                subtitle = "首次使用请安装后台服务,确认一次管理员权限后即可使用"; primary = "安装后台服务";
                break;
            case ServiceAvailability.NeedRepair:
                tile = new(Tone.Warn, Glyph.Bang, Flow.None); title = "后台服务未运行";
                subtitle = "点「修复后台服务」把它启动起来(需管理员确认一次)"; primary = "修复后台服务"; tray = TrayIcon.Warn;
                break;
            case ServiceAvailability.NeedUpgrade:
                tile = new(Tone.N, Glyph.Plug, Flow.None); title = "可安装新版本";
                subtitle = "这个文件比电脑上装的版本新"; primary = "安装这个版本";
                break;
            case ServiceAvailability.Unavailable:
                tile = new(Tone.Bad, Glyph.X, Flow.None); title = snapshot.Status;
                subtitleTone = Tone.Bad; primary = "重新连接后台服务"; tray = TrayIcon.Bad;
                break;
            case ServiceAvailability.Ready:
                switch (snapshot.State)
                {
                    case ConnectionState.Disconnected:
                        primary = "连接";
                        subtitle = snapshot.RoutingMode == "apps"
                            ? $"点「连接」后,指定的 {snapshot.RoutingApps.Length} 个程序从澳洲出口上网"
                            : "点「连接」后,所有程序都从澳洲出口上网";
                        break;
                    case ConnectionState.Connecting:
                        title = "正在连接"; tile = new(Tone.Info, Glyph.Bars, Flow.Forward); primary = "断开"; tray = TrayIcon.Info;
                        break;
                    case ConnectionState.Connected:
                        title = "已连接"; tile = new(Tone.Ok, Glyph.Check, Flow.None, true); primary = "断开"; tray = TrayIcon.Ok;
                        if (snapshot.GuardStatus is not ("" or "正常"))
                        {
                            subtitle = snapshot.GuardStatus;
                            subtitleTone = IsPatrolRetry(snapshot.GuardStatus) ? Tone.Warn : Tone.Bad;
                            tray = TrayIcon.Warn;
                        }
                        else (subtitle, subtitleTone) = ConnectedSubtitle(snapshot);
                        break;
                    case ConnectionState.Reconnecting:
                        title = "正在重连"; tile = new(Tone.Info, Glyph.Spin, Flow.Reverse); primary = "断开"; tray = TrayIcon.Info;
                        break;
                    case ConnectionState.NeedsLogin:
                        title = "需要重新登录"; tile = new(Tone.Warn, Glyph.Ask, Flow.Fast); subtitleTone = Tone.Warn; tray = TrayIcon.Warn; account = true;
                        break;
                    case ConnectionState.NeedsManual:
                        title = "需要处理"; tile = new(Tone.Bad, Glyph.Bang, Flow.None); subtitleTone = Tone.Bad; tray = TrayIcon.Bad;
                        break;
                }
                break;
        }
        var trayText = (isTestBuild ? "澳洲出口客户端(测试包) · " : "澳洲出口客户端 · ") + title;
        if (trayText.Length > 63) trayText = trayText[..63];
        return new(tile, title, subtitle, subtitleTone, primary,
            primary switch { "连接" => "正在连接", "断开" => "正在断开", _ => "正在处理" }, account, tray, trayText, rows);
    }

    private static (string, Tone) ConnectedSubtitle(ControlSnapshot s) => s.ExitStatus switch
    {
        "已核验" => ($"出口 {s.ExitIp} · 与澳洲节点一致", Tone.N),
        "已核验(后台服务出口)" => ($"出口 {s.ExitIp} · 与澳洲节点一致(仅证明后台服务出口)", Tone.N),
        "核验中" => ("正在核验出口…", Tone.N),
        "无法核验" => ("出口无法核验(隧道内暂无回应)", Tone.Warn),
        "不一致" or "不一致(后台服务出口)" => ($"出口 {s.ExitIp} 与澳洲节点不一致,请联系管理员", Tone.Bad),
        _ => (s.Message, Tone.N)
    };

    private static StatusRow Row(string label, Tone tone, Glyph glyph, string text, string right = "", bool dim = false) =>
        new(label, new(tone, glyph, Flow.None, Dim: dim), text, tone is Tone.Bad or Tone.Warn ? tone : Tone.N, right);

    private static StatusRow Exit(ControlSnapshot s) => s.ExitStatus switch
    {
        "核验中" => Row("出口 IP", Tone.Info, Glyph.Dots, "核验中…"),
        "已核验" => Row("出口 IP", Tone.Ok, Glyph.Check, $"{s.ExitIp} · 与澳洲节点一致", "5 分钟后复查"),
        "已核验(后台服务出口)" => Row("出口 IP", Tone.Ok, Glyph.Check, $"{s.ExitIp} · 与澳洲节点一致(仅证明后台服务出口)"),
        "不一致" or "不一致(后台服务出口)" => Row("出口 IP", Tone.Bad, Glyph.Bang, $"{s.ExitIp} · 与澳洲节点不一致,请联系管理员"),
        "无法核验" => Row("出口 IP", Tone.Warn, Glyph.Ask, "无法核验(隧道内暂无回应)"),
        _ => Row("出口 IP", Tone.N, Glyph.Ring, "待检测")
    };

    private static bool IsPatrolRetry(string value) => value is "巡检失败,下一轮重试" or "巡检失败，下一轮重试";
    /// <summary>测试包的断网保护一行固定标注已关闭,不看快照。</summary>
    private static StatusRow TestBuildGuard() => Row("断网保护", Tone.Warn, Glyph.Ask, "测试包已关闭,断线时会直连");
    private static StatusRow Guard(ControlSnapshot s)
    {
        if (!s.ProtectionActive) return Row("断网保护", Tone.N, Glyph.Ring, "未启用,连接时自动开启");
        if (s.State == ConnectionState.NeedsLogin) return Row("断网保护", Tone.Ok, Glyph.Check, "保持中(到期后不撤)");
        if (s.GuardStatus.Length == 0) return Row("断网保护", Tone.Ok, Glyph.Check, "已开启,60 秒后首次巡检");
        if (s.GuardStatus == "正常") return Row("断网保护", Tone.Ok, Glyph.Check, "正常,每 60 秒巡检一次");
        return IsPatrolRetry(s.GuardStatus)
            ? Row("断网保护", Tone.Warn, Glyph.Ask, s.GuardStatus)
            : Row("断网保护", Tone.Bad, Glyph.Bang, s.GuardStatus);
    }

    private static StatusRow SelfCheck(ControlSnapshot s)
    {
        var (tone, glyph) = s.SelfCheckStatus switch
        {
            "未检测" => (Tone.N, Glyph.Ring), "检测中" => (Tone.Info, Glyph.Dots),
            var value when value.Contains("未通过") => (Tone.Bad, Glyph.X),
            var value when value.Contains("未能检查") => (Tone.Warn, Glyph.Ask),
            _ => (Tone.Ok, Glyph.Check)
        };
        return Row("环境自检", tone, glyph, s.SelfCheckStatus, "看明细在「环境一致」");
    }

    private static StatusRow Environment(ControlSnapshot s)
    {
        if (s.EnvironmentStatus.Contains("失败")) return Row("环境一致性", Tone.Bad, Glyph.Bang, s.EnvironmentStatus);
        if (!s.EnvironmentEnabled || s.EnvironmentStatus == "未启用") return Row("环境一致性", Tone.N, Glyph.Ring, "未启用", dim: true);
        return s.EnvironmentStatus == "已切换到澳洲时区与浏览器策略"
            ? Row("环境一致性", Tone.Ok, Glyph.Check, "已应用:澳洲东部时区、Chrome 与 Edge 首选语言")
            : Row("环境一致性", Tone.N, Glyph.Ring, s.EnvironmentStatus);
    }
}
