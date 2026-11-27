using System.Text.RegularExpressions;

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

    private static string Clean(string message)
    {
        string text;
        try
        {
            text = LineBreaks.Replace(message, " | ");
            text = Ipv4.Replace(text, "[地址]");
            text = UserFolder.Replace(text, "$1[用户]");
        }
        catch (RegexMatchTimeoutException) { text = ""; }
        text = text.Trim();
        return text.Length > MaxMessageLength ? text[..MaxMessageLength] + "…" : text;
    }
}
