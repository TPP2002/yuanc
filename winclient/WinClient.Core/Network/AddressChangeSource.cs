using System.Net.NetworkInformation;

namespace WinClient.Core.Network;

/// <summary>本机网卡地址有变化时发一次通知;只是个信号,不带任何地址。</summary>
public interface IAddressChangeSource
{
    event Action? Changed;
}

/// <summary>接系统的地址变化通知。回调在系统线程上,订阅者不能在里面做重活。</summary>
public sealed class SystemAddressChangeSource : IAddressChangeSource, IDisposable
{
    public event Action? Changed;
    public SystemAddressChangeSource() => NetworkChange.NetworkAddressChanged += OnChanged;
    private void OnChanged(object? sender, EventArgs e) => Changed?.Invoke();
    public void Dispose() => NetworkChange.NetworkAddressChanged -= OnChanged;
}
