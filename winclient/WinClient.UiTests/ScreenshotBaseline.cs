using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace WinClient.UiTests;

internal static class ScreenshotBaseline
{
    // 交互会话的基准与服务账户非交互渲染可能有字体平滑细差，容差固定，不自动放宽。
    internal const int ChannelTolerance = 16;
    internal const double MaxDifferentRatio = 0.001;

    internal sealed record CompareResult(bool SizeMatches, int DifferentPixels, int TotalPixels)
    {
        public double Ratio => TotalPixels == 0 ? 1 : (double)DifferentPixels / TotalPixels;
        public bool Passed => SizeMatches && Ratio <= MaxDifferentRatio;
    }

    internal static CompareResult Compare(int width, int height, int[] actualBgra,
        int baseWidth, int baseHeight, int[] baselineBgra, int[]? diffOut = null)
    {
        var total = checked(width * height);
        if (width != baseWidth || height != baseHeight)
        {
            if (diffOut is not null) Array.Fill(diffOut, unchecked((int)0xFFFF0000), 0, total);
            return new CompareResult(false, total, total);
        }

        var differentPixels = 0;
        for (var i = 0; i < total; i++)
        {
            var actual = actualBgra[i];
            var baseline = baselineBgra[i];
            var different = false;
            for (var shift = 0; shift < 32; shift += 8)
                if (Math.Abs(((actual >> shift) & 255) - ((baseline >> shift) & 255)) > ChannelTolerance)
                    different = true;
            if (different) differentPixels++;
            if (diffOut is not null)
            {
                var gray = (299 * ((actual >> 16) & 255) + 587 * ((actual >> 8) & 255) + 114 * (actual & 255)) / 2000;
                diffOut[i] = different ? unchecked((int)0xFFFF0000)
                    : unchecked((int)0xFF000000) | (gray << 16) | (gray << 8) | gray;
            }
        }
        return new CompareResult(true, differentPixels, total);
    }

    internal static (int Width, int Height, int[] Pixels) ReadPng(string path)
    {
        using var stream = File.OpenRead(path);
        var decoder = new PngBitmapDecoder(stream, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        var bitmap = new FormatConvertedBitmap(decoder.Frames[0], PixelFormats.Pbgra32, null, 0);
        var pixels = new int[bitmap.PixelWidth * bitmap.PixelHeight];
        bitmap.CopyPixels(pixels, bitmap.PixelWidth * 4, 0);
        return (bitmap.PixelWidth, bitmap.PixelHeight, pixels);
    }

    internal static string BaselineDirectory(string repositoryRoot) =>
        Path.Combine(repositoryRoot, "winclient", "WinClient.UiTests", "Baselines");

    internal static bool UpdateRequested => Environment.GetEnvironmentVariable("YC_UPDATE_UI_BASELINE") == "1";
}
