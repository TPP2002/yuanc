using System.Text.RegularExpressions;
using WinClient.Core.State;

namespace WinClient.Core.Client;

/// <summary>
/// 连接记录的文本加工:只保留异常类型与处理过的消息,不写节点地址、出口地址、令牌或配对内容。
/// </summary>
public static class ConnectJournal
{
    internal const int MaxDepth = 4;
    internal const int MaxMessageLength = 300;
    private static readonly Regex LineBreaks = new("(\r\n|\r|\n)+", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Ipv4 = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex UserFolder = new(@"(?i)([A-Z]:\\Users\\)([^\\/\s]+)", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    /// <summary>从外到内最多四层,每层写成「类型短名:消息」,层间用「 &lt;- 」连接。</summary>
    public static string Describe(Exception ex)
    {
        var parts = new List<string>();
        Exception? current = ex;
        for (var depth = 0; current is not null && depth < MaxDepth; depth++)
        {
            parts.Add(current.GetType().Name + "：" + Clean(current.Message));
            current = current.InnerException;
        }
        return string.Join(" <- ", parts);
    }

    /// <summary>处理要写进连接记录的文字:换行、IPv4 与用户目录名脱敏,去首尾空白,超长截断。</summary>
    public static string Clean(string? message)
    {
        string text;
        try
        {
            text = LineBreaks.Replace(message ?? "", " | ");
            text = Ipv4.Replace(text, "[地址]");
            text = UserFolder.Replace(text, "$1[用户]");
        }
        catch (RegexMatchTimeoutException) { text = ""; }
        text = text.Trim();
        return text.Length > MaxMessageLength ? text[..MaxMessageLength] + "…" : text;
    }

    /// <summary>状态名:记录里只写中文名,不写枚举名。</summary>
    public static string StateName(ConnectionState state) => state switch
    {
        ConnectionState.Disconnected => "未连接",
        ConnectionState.Connecting => "连接中",
        ConnectionState.Connected => "已连接",
        ConnectionState.Reconnecting => "重连中",
        ConnectionState.NeedsLogin => "需重新登录",
        ConnectionState.NeedsManual => "需人工处理",
        _ => state.ToString()
    };

    /// <summary>动作名:退避带上安排好的秒数。</summary>
    public static string EffectName(ConnectionEffect effect) => effect.Kind switch
    {
        EffectKind.ApplyKillSwitch => "套用断网保护",
        EffectKind.UpdateKillSwitchNode => "更新节点规则",
        EffectKind.RemoveKillSwitch => "撤销断网保护",
        EffectKind.StopTunnel => "停止隧道",
        EffectKind.StartTunnel => "启动隧道",
        EffectKind.ShowMessage => "显示提示",
        EffectKind.ScheduleBackoff => "安排退避 " + (effect.Delay is { } delay ? (long)delay.TotalSeconds : 0L) + " 秒",
        _ => effect.Kind.ToString()
    };
}
