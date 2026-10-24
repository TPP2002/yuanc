using Xunit;

namespace WinClient.UiTests;

public sealed class ScreenshotBaselineTests
{
    [Fact]
    public void 完全相同没有不同像素()
    {
        int[] pixels = [unchecked((int)0xFF123456), 0x12345678];
        var result = ScreenshotBaseline.Compare(2, 1, pixels, 2, 1, pixels);
        Assert.True(result.Passed);
        Assert.Equal(0, result.DifferentPixels);
    }

    [Fact]
    public void 四通道正负十六噪声均通过()
    {
        var baseline = Enumerable.Repeat(unchecked((int)0x80808080), 16).ToArray();
        var actual = Enumerable.Range(0, 16).Select(mask =>
        {
            var pixel = 0;
            for (var channel = 0; channel < 4; channel++)
                pixel |= (128 + ((mask & (1 << channel)) == 0 ? -16 : 16)) << (channel * 8);
            return pixel;
        }).ToArray();
        var result = ScreenshotBaseline.Compare(4, 4, actual, 4, 4, baseline);
        Assert.True(result.Passed);
        Assert.Equal(0, result.DifferentPixels);
    }

    [Fact]
    public void 三十乘三十区域差四十判失败()
    {
        var baseline = new int[100 * 100];
        var actual = new int[100 * 100];
        for (var y = 20; y < 50; y++)
            for (var x = 20; x < 50; x++) actual[y * 100 + x] = 40;
        var result = ScreenshotBaseline.Compare(100, 100, actual, 100, 100, baseline);
        Assert.False(result.Passed);
        Assert.Equal(900, result.DifferentPixels);
    }

    [Fact]
    public void 尺寸不同判全部不同()
    {
        var result = ScreenshotBaseline.Compare(2, 3, new int[6], 3, 2, new int[6]);
        Assert.False(result.SizeMatches);
        Assert.False(result.Passed);
        Assert.Equal(6, result.TotalPixels);
        Assert.Equal(result.TotalPixels, result.DifferentPixels);
    }

    [Fact]
    public void 千分之一通过多一个失败()
    {
        var baseline = new int[1000 * 10];
        var actual = new int[1000 * 10];
        Array.Fill(actual, 17, 0, 10);
        var boundary = ScreenshotBaseline.Compare(1000, 10, actual, 1000, 10, baseline);
        Assert.True(boundary.Passed);
        Assert.Equal(10, boundary.DifferentPixels);
        Assert.Equal(0.001, boundary.Ratio);
        actual[10] = 17;
        var over = ScreenshotBaseline.Compare(1000, 10, actual, 1000, 10, baseline);
        Assert.False(over.Passed);
        Assert.Equal(11, over.DifferentPixels);
    }

    [Fact]
    public void 差异标红相同像素灰度减半()
    {
        var diff = new int[2];
        ScreenshotBaseline.Compare(2, 1, [40, unchecked((int)0xFF808080)],
            2, 1, [0, unchecked((int)0xFF808080)], diff);
        Assert.Equal(unchecked((int)0xFFFF0000), diff[0]);
        Assert.Equal(unchecked((int)0xFF404040), diff[1]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(24)]
    public void 任一通道超过十六即不同(int shift)
    {
        var result = ScreenshotBaseline.Compare(1, 1, [17 << shift], 1, 1, [0]);
        Assert.False(result.Passed);
        Assert.Equal(1, result.DifferentPixels);
    }
}
