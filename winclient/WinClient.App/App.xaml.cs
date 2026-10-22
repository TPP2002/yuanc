using System.Windows;
using System.ComponentModel;
using WinClient.App.Presentation;
using WinClient.App.Themes;
using Forms = System.Windows.Forms;

namespace WinClient.App;

public partial class App : Application
{
    public bool StartInTray { get; init; }
    private EventWaitHandle? showWindow;
    private RegisteredWaitHandle? notification;
    private Forms.NotifyIcon? tray;
    private MainWindow? window;
    private readonly Dictionary<TrayIcon, System.Drawing.Icon> trayIcons = [];
    protected override void OnStartup(StartupEventArgs e)
    {
        showWindow = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\YuanC-ShowWindow", out var created);
        if (!created)
        {
            showWindow.Set(); Shutdown(); return;
        }
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        base.OnStartup(e);
        ThemeManager.Apply(Resources, ThemeManager.Detect());
        ThemeManager.Start();
        foreach (var kind in Enum.GetValues<TrayIcon>())
        {
            var uri = new Uri($"pack://application:,,,/WinClient.App;component/Assets/tray-{kind.ToString().ToLowerInvariant()}.ico");
            using var stream = GetResourceStream(uri)!.Stream;
            using var icon = new System.Drawing.Icon(stream);
            trayIcons.Add(kind, (System.Drawing.Icon)icon.Clone());
        }
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
        tray = new Forms.NotifyIcon { Icon = trayIcons[TrayIcon.N], Text = "澳洲出口客户端", ContextMenuStrip = menu, Visible = true };
        window.Model.PropertyChanged += ModelChanged;
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
    private void ModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(MainViewModel.Hero) || tray is null || window is null) return;
        tray.Icon = trayIcons[window.Model.Hero.Tray];
        tray.Text = window.Model.Hero.TrayText;
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
        ThemeManager.Stop();
        if (window is not null) window.Model.PropertyChanged -= ModelChanged;
        notification?.Unregister(null);
        showWindow?.Dispose();
        if (tray is not null) { tray.Visible = false; tray.ContextMenuStrip?.Dispose(); tray.Dispose(); }
        foreach (var icon in trayIcons.Values) icon.Dispose();
        trayIcons.Clear();
        window?.Model.Dispose();
        base.OnExit(e);
    }
}
