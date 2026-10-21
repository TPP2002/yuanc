using WinClient.Core.Logging;

namespace WinClient.Core.Update;

/// <summary>A full log disk must not interrupt service rollback; pending/history remain the transaction records.</summary>
public sealed class UpdateLog(ILog destination) : ILog
{
    private readonly RedactingLog redacted = new(destination);
    public void Write(string message)
    {
        try { redacted.Write(message); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
