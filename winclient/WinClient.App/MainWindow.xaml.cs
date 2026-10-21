using System.ComponentModel;
using System.Windows;
using Microsoft.Win32;

namespace WinClient.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel model;
    public MainViewModel Model => model;
    public MainWindow()
    {
        InitializeComponent();
        model = new MainViewModel(ChoosePairingFile);
        DataContext = model;
    }
    private string? ChoosePairingFile()
    {
        var dialog = new OpenFileDialog { Title = "导入配对文件", Filter = "配对文件 (*.ycpair)|*.ycpair", CheckFileExists = true, Multiselect = false };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "导出防火墙审计", Filter = "诊断文件 (*.json)|*.json", FileName = "防火墙审计.json" };
        if (!model.IsBusy && dialog.ShowDialog(this) == true) await model.ExportAuditAsync(dialog.FileName);
    }
    protected override void OnClosing(CancelEventArgs e)
    {
        e.Cancel = true;
        Hide();
        base.OnClosing(e);
    }
}
