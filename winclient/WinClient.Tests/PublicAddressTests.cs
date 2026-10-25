using System.Net;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

public sealed class PublicAddressTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("100.63.255.255", true)]
    [InlineData("100.128.0.1", true)]
    [InlineData("172.15.0.1", true)]
    [InlineData("172.32.0.1", true)]
    [InlineData("198.20.0.1", true)]
    [InlineData("223.255.255.255", true)]
    [InlineData("0.1.2.3", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("100.127.255.255", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.19.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("192.0.0.8", false)]
    [InlineData("192.0.2.5", false)]
    [InlineData("192.168.1.5", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("198.19.255.255", false)]
    [InlineData("198.51.100.7", false)]
    [InlineData("203.0.113.9", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("239.255.255.250", false)]
    [InlineData("240.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("240e::1", true)]
    [InlineData("2400:3200::1", true)]
    [InlineData("3fff::1", true)]
    [InlineData("2001:db8::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fdfe:dcba:9876::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("::1", false)]
    [InlineData("::", false)]
    [InlineData("4000::1", false)]
    [InlineData("::ffff:8.8.8.8", true)]
    [InlineData("::ffff:192.168.1.5", false)]
    [InlineData("::ffff:100.64.0.1", false)]
    public void ClassifiesPublicAndReservedAddresses(string text, bool expected)
    {
        Assert.Equal(expected, PublicAddress.IsPublic(IPAddress.Parse(text)));
    }
}
