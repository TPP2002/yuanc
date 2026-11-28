using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

/// <summary>地址变化来源只转发一个信号,不做重活;订阅与释放要干净。</summary>
public class AddressChangeSourceTests
{
    [Fact]
    public void SystemSourceSubscribesAndDisposesCleanly()
    {
        var source = new SystemAddressChangeSource();
        var raised = 0;
        source.Changed += () => Interlocked.Increment(ref raised);
        source.Dispose();
        source.Dispose();
        Assert.Equal(0, Volatile.Read(ref raised));
        Assert.NotNull(source);
    }
}
