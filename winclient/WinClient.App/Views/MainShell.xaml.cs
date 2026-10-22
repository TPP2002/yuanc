using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinClient.App.Themes;

namespace WinClient.App.Views;

public partial class MainShell : UserControl
{
    public static RoutedUICommand ExportDiagnosticsCommand { get; } = new("导出诊断", "ExportDiagnostics", typeof(MainShell));
    private INotifyPropertyChanged? observed;
    public MainShell()
    {
        InitializeComponent();
        Loaded += (_, _) => Observe(DataContext);
        Unloaded += (_, _) => Observe(null);
        DataContextChanged += (_, _) => { if (IsLoaded) Observe(DataContext); };
    }
    private void Observe(object? model)
    {
        if (observed is not null) observed.PropertyChanged -= Changed;
        observed = model as INotifyPropertyChanged;
        if (observed is not null) observed.PropertyChanged += Changed;
    }
    private void Changed(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == "CurrentPage") EntranceMotion.Play(PageHost, 180, 6);
    }
}
