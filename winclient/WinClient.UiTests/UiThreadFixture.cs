using System.Windows;
using System.Windows.Threading;
using Xunit;

namespace WinClient.UiTests;

[CollectionDefinition("界面线程", DisableParallelization = true)]
public sealed class UiThreadCollection : ICollectionFixture<UiThreadFixture>;

public sealed class UiThreadFixture : IDisposable
{
    private readonly Thread thread;
    private readonly TaskCompletionSource<Dispatcher> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public UiThreadFixture()
    {
        thread = new Thread(() =>
        {
            try
            {
                var resourceAssembly = typeof(WinClient.App.MainWindow).Assembly;
                if (Application.ResourceAssembly != resourceAssembly)
                {
                    try { Application.ResourceAssembly = resourceAssembly; }
                    catch (InvalidOperationException) { /* 测试宿主已锁定入口程序集，资源用程序集名定位。 */ }
                }
                if (Application.Current is null) _ = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                ready.SetResult(Dispatcher.CurrentDispatcher);
                Dispatcher.Run();
            }
            catch (Exception ex) { ready.TrySetException(ex); }
        }) { IsBackground = true, Name = "界面测试线程" };
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
    }
    public void Invoke(Action action) => ready.Task.GetAwaiter().GetResult().Invoke(action);
    public void Dispose()
    {
        var dispatcher = ready.Task.GetAwaiter().GetResult();
        dispatcher.Invoke(() => Application.Current.Shutdown());
        dispatcher.BeginInvokeShutdown(DispatcherPriority.Send);
        thread.Join();
    }
}
