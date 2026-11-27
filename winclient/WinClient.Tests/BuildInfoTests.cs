using System.Reflection;
using WinClient.Core.Client;
using Xunit;

namespace WinClient.Tests;

public sealed class BuildInfoTests
{
    [Theory]
    [InlineData(false, null, true)]
    [InlineData(false, true, true)]
    [InlineData(false, false, false)]
    [InlineData(true, null, false)]
    [InlineData(true, true, false)]
    [InlineData(true, false, false)]
    public void KeepOnStartupTruthTable(bool testBuild, bool? desired, bool expected)
        => Assert.Equal(expected, BuildInfo.KeepOnStartup(testBuild, desired));

    [Fact]
    public void IsTestBuildReadsMetadata()
    {
        Assert.False(BuildInfo.IsTestBuild(Array.Empty<AssemblyMetadataAttribute>()));
        Assert.True(BuildInfo.IsTestBuild([new("YuanC.TestBuild", "true")]));
        Assert.True(BuildInfo.IsTestBuild([new("YuanC.TestBuild", "TRUE")]));
        Assert.False(BuildInfo.IsTestBuild([new("YuanC.TestBuild", "false")]));
        Assert.False(BuildInfo.IsTestBuild([new("YuanC.Other", "true")]));
        Assert.False(BuildInfo.IsTestBuild((Assembly?)null));
        Assert.False(BuildInfo.IsTestBuild(typeof(BuildInfoTests).Assembly));
    }
}
