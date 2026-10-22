using WinClient.Core.EnvironmentSupport;
using Xunit;

namespace WinClient.Tests;

public sealed class EnvironmentPolicyTests
{
    private static EnvironmentPolicy Local => new(false, new("China Standard Time", ["en-NZ", "en"]), "AU");

    [Fact]
    public void MissingNodeOrEmptyFieldsReturnOriginalPolicy()
    {
        var policy = Local;
        Assert.Same(policy, policy.ForNode(null));
        Assert.Same(policy, policy.ForNode(TestData.Node()));
    }

    [Theory]
    [InlineData("", "China Standard Time")]
    [InlineData("W. Australia Standard Time", "W. Australia Standard Time")]
    [InlineData("Mars/Olympus", "China Standard Time")]
    public void NodeOverridesCountryAndRecognizedTimeZoneWithoutChangingLanguages(string zone, string expected)
    {
        var policy = Local;
        var resolved = policy.ForNode(TestData.Node(timeZone: zone, country: "NZ"));
        Assert.NotSame(policy, resolved);
        Assert.Equal("NZ", resolved.ExpectedCountry);
        Assert.Equal(expected, resolved.Target.TimeZoneId);
        Assert.Equal(policy.Target.Languages, resolved.Target.Languages);
        Assert.Equal(policy.Enabled, resolved.Enabled);
        Assert.Equal("China Standard Time", policy.Target.TimeZoneId);
        Assert.Equal("AU", policy.ExpectedCountry);
    }

    [Fact]
    public void IanaTimeZoneConvertsWhenSupportedOtherwiseUsesLocalConfiguration()
    {
        var policy = Local;
        var resolved = policy.ForNode(TestData.Node(timeZone: "Australia/Perth"));
        Assert.Equal(TimeZoneInfo.TryConvertIanaIdToWindowsId("Australia/Perth", out _)
            ? "W. Australia Standard Time" : policy.Target.TimeZoneId, resolved.Target.TimeZoneId);
        Assert.Equal(policy.ExpectedCountry, resolved.ExpectedCountry);
        Assert.Equal(policy.Target.Languages, resolved.Target.Languages);
    }
}
