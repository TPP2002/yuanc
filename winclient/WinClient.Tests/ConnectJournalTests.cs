using WinClient.Core.Client;
using Xunit;

namespace WinClient.Tests;

public sealed class ConnectJournalTests
{
    [Fact]
    public void DescribeChainsTypesAndScrubsAddressesAndUserFolders()
    {
        var chain = new InvalidOperationException("外层 203.0.113.9", new IOException("C:\\Users\\alice\\x\r\n第二行"));
        Assert.Equal("InvalidOperationException：外层 [地址] <- IOException：C:\\Users\\[用户]\\x | 第二行",
            ConnectJournal.Describe(chain));

        var longMessage = new string('长', 400);
        Assert.Equal("InvalidOperationException：" + longMessage[..300] + "…",
            ConnectJournal.Describe(new InvalidOperationException(longMessage)));

        var deep = new InvalidOperationException("四", new InvalidOperationException("三",
            new InvalidOperationException("二", new InvalidOperationException("一",
                new InvalidOperationException("零", new InvalidOperationException("负"))))));
        var described = ConnectJournal.Describe(deep);
        Assert.Equal(4, described.Split(" <- ").Length);
        Assert.Contains("四", described);
        Assert.Contains("一", described);
        Assert.DoesNotContain("零", described);
        Assert.DoesNotContain("负", described);
    }
}
