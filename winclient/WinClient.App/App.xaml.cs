using System.Windows;
using Forms = System.Windows.Forms;

namespace WinClient.App;

public partial class App : Application
{
    public bool StartInTray { get; init; }
    private EventWaitHandle? showWindow;
    private RegisteredWaitHandle? notification;
    private Forms.NotifyIcon? tray;
    private MainWindow? window;
    protected override void OnStartup(StartupEventArgs e)
    {
        showWindow = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\YuanC-ShowWindow", out var created);
        if (!created)
        {
            showWindow.Set(); Shutdown(); return;
        }
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        base.OnStartup(e);
        window = new MainWindow();
        MainWindow = window;
        notification = ThreadPool.RegisterWaitForSingleObject(showWindow, (_, _) =>
        {
            if (!Dispatcher.HasShutdownStarted) Dispatcher.InvokeAsync(ShowWindow);
        }, null, Timeout.Infinite, executeOnlyOnce: false);
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("打开窗口", null, (_, _) => ShowWindow());
        var connect = menu.Items.Add("连接", null, async (_, _) => await window.Model.ConnectFromTrayAsync());
        var disconnect = menu.Items.Add("断开", null, async (_, _) => await window.Model.DisconnectFromTrayAsync());
        menu.Items.Add("退出界面(隧道不受影响)", null, (_, _) => Shutdown());
        menu.Opening += (_, _) => { connect.Enabled = window.Model.CanUseConnection; disconnect.Enabled = window.Model.CanUseConnection; };
        tray = new Forms.NotifyIcon { Icon = System.Drawing.SystemIcons.Application, Text = "澳洲出口客户端", ContextMenuStrip = menu, Visible = true };
        tray.DoubleClick += (_, _) => ShowWindow();
        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            MessageBox.Show("界面发生异常，即将关闭；后台连接由后台服务继续管理。", "澳洲出口客户端");
            Shutdown(1);
        };
        if (!StartInTray) ShowWindow();
        _ = InitializeWindowAsync();
    }
    private async Task InitializeWindowAsync()
    {
        try { await window!.Model.InitializeAsync(); }
        catch (Exception)
        {
            MessageBox.Show("界面未能初始化，请重新打开客户端或联系管理员。", "澳洲出口客户端");
            Shutdown(1);
        }
    }
    private void ShowWindow()
    {
        if (window is null) return;
        window.Show();
        if (window.WindowState == WindowState.Minimized) window.WindowState = WindowState.Normal;
        window.Activate();
    }
    protected override void OnExit(ExitEventArgs e)
    {
        notification?.Unregister(null);
        showWindow?.Dispose();
        if (tray is not null) { tray.Visible = false; tray.ContextMenuStrip?.Dispose(); tray.Dispose(); }
        window?.Model.Dispose();
        base.OnExit(e);
    }
}