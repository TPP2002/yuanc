using System.Windows;
using System.Windows.Controls;

namespace WinClient.App.Views;

public partial class RoutingPage : UserControl
{
    public RoutingPage() => InitializeComponent();
    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel model || sender is not Button { DataContext: string path }) return;
        model.SelectedRoutingApp = path;
        if (model.RemoveRoutingAppCommand.CanExecute(null)) model.RemoveRoutingAppCommand.Execute(null);
    }
}
