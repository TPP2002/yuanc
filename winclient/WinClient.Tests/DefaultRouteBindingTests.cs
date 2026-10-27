using WinClient.Core.Firewall;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

public sealed class DefaultRouteBindingTests
{
    [Fact]
    public void PicksLowestMetricPhysicalRoute()
    {
        DefaultRoute[] routes = [new(8, "物理甲", 30), new(7, "物理乙", 10), new(6, "物理丙", 10)];
        Assert.Equal(6, DefaultRouteBinding.Pick(routes, 1));
    }

    [Fact]
    public void SkipsLoopbackAndTunnel()
    {
        DefaultRoute[] routes = [new(1, "回环", 0), new(2, KillSwitchPlanner.TunAlias.ToLowerInvariant(), 1), new(4, "物理", 50)];
        Assert.Equal(4, DefaultRouteBinding.Pick(routes, 1));
    }

    [Fact]
    public void ReturnsNullWithoutCandidates()
    {
        Assert.Null(DefaultRouteBinding.Pick([], 1));
        Assert.Null(DefaultRouteBinding.Pick([new(1, "回环", 0), new(2, KillSwitchPlanner.TunAlias, 1)], 1));
    }

    [Fact]
    public void ReadSystemDoesNotThrow()
    {
        Assert.Null(Record.Exception(() => { Assert.NotNull(DefaultRouteBinding.ReadSystem()); }));
    }
}
