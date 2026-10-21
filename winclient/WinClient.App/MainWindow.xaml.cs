using System.ComponentModel;
using System.Windows;
using Microsoft.Win32;

namespace WinClient.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel model;
    public MainWindow()
    {
        InitializeComponent();
        model = new MainViewModel(ChoosePairingFile);
        DataContext = model;
        Loaded += async (_, _) => await model.InitializeAsync();
    }
    private string? ChoosePairingFile()
    {
        var dialog = new OpenFileDialog { Title = "导入配对文件", Filter = "配对文件 (*.ycpair)|*.ycpair", CheckFileExists = true, Multiselect = false };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "导出防火墙审计", Filter = "诊断文件 (*.json)|*.json", FileName = "防火墙审计.json" };
        if (dialog.ShowDialog(this) == true) model.ExportAudit(dialog.FileName);
    }
    protected override void OnClosing(CancelEventArgs e)
    {
        if (model.IsBusy)
        {
            e.Cancel = true;
            MessageBox.Show(this, "正在处理连接操作，请稍候。", "澳洲出口客户端");
            return;
        }
        model.Dispose();
        base.OnClosing(e);
    }
}
