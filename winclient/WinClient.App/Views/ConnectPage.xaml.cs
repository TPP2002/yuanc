using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Runtime.CompilerServices;
using WinClient.App.Presentation;
using WinClient.App.Themes;

namespace WinClient.App.Views;

public partial class ConnectPage : UserControl
{
    private sealed class FirstDisplay { public bool Shown; }
    private static readonly ConditionalWeakTable<object, FirstDisplay> firstDisplays = new();
    private string? previousExit;
    public ConnectPage()
    {
        InitializeComponent();
        Rows.ItemContainerGenerator.StatusChanged += (_, _) =>
        {
            if (DataContext is null || Rows.ItemContainerGenerator.Status != GeneratorStatus.ContainersGenerated || Rows.Items.Count != 4) return;
            var first = firstDisplays.GetValue(DataContext, _ => new FirstDisplay());
            if (first.Shown) return;
            first.Shown = true;
            for (var i = 0; i < 4; i++)
                if (Rows.ItemContainerGenerator.ContainerFromIndex(i) is FrameworkElement row) EntranceMotion.Play(row, 140, 0, i * 30);
        };
    }
    private void RowTextUpdated(object sender, DataTransferEventArgs e)
    {
        if (sender is not TextBlock text || text.DataContext is not StatusRow { Label: "出口 IP" }) return;
        if (previousExit is not null && previousExit != text.Text) EntranceMotion.Play(text, 300, 4);
        previousExit = text.Text;
    }
}
