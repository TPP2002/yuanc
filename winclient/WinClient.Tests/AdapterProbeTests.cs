using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class AdapterProbeTests
{
    [Fact]
    public void 系统网卡快照包含名称和合法前缀()
    {
        if (!OperatingSystem.IsWindows()) return;
        var adapters = new SystemAdapterProbe().Snapshot();
        Assert.NotNull(adapters);
        Assert.All(adapters, adapter =>
        {
            Assert.False(string.IsNullOrWhiteSpace(adapter.Name));
            Assert.All(adapter.Ipv4, address => Assert.InRange(address.PrefixLength, 0, 32));
        });
    }

    [Fact]
    public void 记录可保存空地址列表且地址按值相等()
    {
        var adapter = new AdapterInfo("空网卡", "虚拟网卡", []);
        Assert.Empty(adapter.Ipv4);
        Assert.Equal(adapter, adapter with { });
        Assert.Equal(new AdapterAddress("172.19.0.1", 30), new AdapterAddress("172.19.0.1", 30));
    }
}
