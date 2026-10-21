using System.Text.RegularExpressions;

namespace WinClient.Core.Logging;

public interface ILog
{
    void Write(string message);
}

public sealed class NullLog : ILog
{
    public static NullLog Instance { get; } = new();
    public void Write(string message) { }
}

/// <summary>Redacts both labelled values and registered opaque secrets before forwarding.</summary>
public sealed class RedactingLog(ILog destination) : ILog
{
    private readonly object gate = new();
    private readonly HashSet<string> secrets = new(StringComparer.Ordinal);
    private static readonly Regex LabelledSecret = new(
        "(?i)([\\\"]?(?:refresh_token|session_token|token|password|hy2_password|uuid|private_key|authorization)[\\\"]?\\s*[:=]\\s*)(?:[\\\"][^\\\"]*[\\\"]|[^\\s,;}]+)",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Bearer = new("(?i)Bearer\\s+[^\\s\\\",;}]+",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public void RegisterSecret(string? value)
    {
        if (!string.IsNullOrEmpty(value))
            lock (gate) secrets.Add(value);
    }

    public void Write(string message)
    {
        lock (gate)
        {
            foreach (var secret in secrets.OrderByDescending(s => s.Length))
                message = message.Replace(secret, "[已隐藏]", StringComparison.Ordinal);
            try
            {
                message = Bearer.Replace(message, "Bearer [已隐藏]");
                message = LabelledSecret.Replace(message, "$1[已隐藏]");
            }
            catch (RegexMatchTimeoutException)
            {
                message = "日志已隐藏：无法在限定时间内完成脱敏。";
            }
            destination.Write(message);
        }
    }
}
