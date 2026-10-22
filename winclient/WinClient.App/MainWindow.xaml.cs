using System.ComponentModel;
using System.Windows;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Input;
using WinClient.App.Themes;
using WinClient.App.Views;

namespace WinClient.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel model;
    public MainViewModel Model => model;
    public MainWindow()
    {
        InitializeComponent();
        model = new MainViewModel(ChoosePairingFile, ChooseProgram);
        DataContext = model;
        CommandBindings.Add(new CommandBinding(MainShell.ExportDiagnosticsCommand, Export_Click,
            (_, e) => e.CanExecute = !model.IsBusy));
        ThemeManager.ThemeChanged += ThemeChanged;
        Closed += (_, _) => ThemeManager.ThemeChanged -= ThemeChanged;
    }
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyTitleBar();
    }
    private void ThemeChanged(object? sender, EventArgs e) => ApplyTitleBar();
    private void ApplyTitleBar()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero) return;
        var dark = ThemeManager.Current == ThemeKind.Dark ? 1 : 0;
        try
        {
            if (DwmSetWindowAttribute(hwnd, 20, ref dark, 4) != 0) _ = DwmSetWindowAttribute(hwnd, 19, ref dark, 4);
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    private string? ChoosePairingFile()
    {
        var dialog = new OpenFileDialog { Title = "导入配对文件", Filter = "配对文件 (*.ycpair)|*.ycpair", CheckFileExists = true, Multiselect = false };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
    private string? ChooseProgram()
    {
        var dialog = new OpenFileDialog { Title = "选择要走澳洲出口的程序", Filter = "程序 (*.exe)|*.exe", CheckFileExists = true, Multiselect = false };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "导出诊断", Filter = "诊断文件 (*.json)|*.json", FileName = "诊断报告.json" };
        if (!model.IsBusy && dialog.ShowDialog(this) == true) await model.ExportAuditAsync(dialog.FileName);
    }
    protected override void OnClosing(CancelEventArgs e)
    {
        e.Cancel = true;
        Hide();
        base.OnClosing(e);
    }
}
