using System.IO;
using WinClient.Core.Logging;
using WinClient.Core.Update;

namespace WinClient.App.Hosting;

public static class UpdateRecovery
{
    public static void Run(UpdateStore store, string currentExe, IUpdateHost host, string appRoot, ILog? logger = null)
    {
        var log = new UpdateLog(logger ?? NullLog.Instance);
        if (!store.HasPending) return;
        var pending = store.ReadPending();
        if (pending is null) { log.Write("更新恢复记录损坏，请联系维护人员。"); return; }
        if (host.Now - pending.StartedAt <= TimeSpan.FromMinutes(10)) return;
        try
        {
            UpdateApplier.ValidatePaths(pending, appRoot);
            if (string.Equals(Path.GetFullPath(currentExe), pending.NewExe, StringComparison.OrdinalIgnoreCase))
                UpdateApplier.Complete(store, pending, host, appRoot, log);
            else if (string.Equals(Path.GetFullPath(currentExe), pending.OldExe, StringComparison.OrdinalIgnoreCase))
            {
                store.MarkBad(pending.NewVersion);
                store.AppendHistory(pending.NewVersion, "rolled_back", host.Now, "新版未完成启动，当前继续使用旧版。");
                store.DeletePending();
            }
            else log.Write("更新记录与当前后台不一致，请联系维护人员。");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        { log.Write("更新收尾未完成，记录已保留，请联系维护人员。"); }
    }
}
