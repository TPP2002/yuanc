using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using WinClient.Core.Logging;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

public static class DiagnosticsRedactor
{
    public const string PublicAddressMark = "[公网地址]";
    public const string UserMark = "[用户]";
    public const string TimedOutMark = "[脱敏超时，内容已隐藏]";

    private static readonly Regex Ipv4 = new(
        @"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
    private static readonly Regex Ipv6 = new(
        @"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
    private static readonly Regex UserDirectory = new(
        @"(?i)([A-Z]:\\{1,2}Users\\{1,2})[^\\/\s""'<>|:*?]+",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));

    /// <summary>给 JSON 原文脱敏，替换后仍是合法 JSON。</summary>
    public static string RedactStructured(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        try
        {
            var result = Ipv4.Replace(text, match =>
                IPAddress.TryParse(match.Value, out var ip) && PublicAddress.IsPublic(ip) ? PublicAddressMark : match.Value);
            result = Ipv6.Replace(result, match =>
                IPAddress.TryParse(match.Value, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
                    && PublicAddress.IsPublic(ip) ? PublicAddressMark : match.Value);
            return UserDirectory.Replace(result, "$1" + UserMark);
        }
        catch (RegexMatchTimeoutException)
        {
            return TimedOutMark;
        }
    }

    /// <summary>给日志行和零散文字脱敏：先隐藏令牌、口令与 Bearer，再做结构化脱敏。</summary>
    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var sink = new LastMessageLog();
        new RedactingLog(sink).Write(text);
        return RedactStructured(sink.Message);
    }

    /// <summary>只记住最后一条消息的日志目的地，用来取回 RedactingLog 写出的结果。</summary>
    private sealed class LastMessageLog : ILog
    {
        public string Message { get; private set; } = "";
        public void Write(string message) => Message = message;
    }
}
