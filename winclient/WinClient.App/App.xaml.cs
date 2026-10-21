using System.Windows;

namespace WinClient.App;

public partial class App : Application
{
    private Mutex? instance;
    protected override void OnStartup(StartupEventArgs e)
    {
        instance = new Mutex(true, @"Global\YuanC-WinClient", out var created);
        if (!created)
        {
            MessageBox.Show("客户端已经运行，请使用已打开的窗口。", "澳洲出口客户端");
            Shutdown();
            return;
        }
        base.OnStartup(e);
    }
    protected override void OnExit(ExitEventArgs e)
    {
        instance?.Dispose();
        base.OnExit(e);
    }
}
