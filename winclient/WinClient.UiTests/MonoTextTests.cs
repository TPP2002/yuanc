using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using WinClient.App.Themes;
using Xunit;

namespace WinClient.UiTests;

[Collection("界面线程")]
public class MonoTextTests(UiThreadFixture ui)
{
    [Theory]
    [InlineData("出口 203.0.113.9 · 与澳洲节点一致", "203.0.113.9")]
    [InlineData("正在下载 1.3.1…", "1.3.1")]
    [InlineData("fdfe:dcba:9876::1/126", "fdfe:dcba:9876::1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("失效:系统防火墙已被关闭", null)]
    [InlineData("5 分钟后复查", null)]
    [InlineData("8 项通过", null)]
    [InlineData("en-AU", null)]
    public void 切片保留原文且只标记地址版本(string text, string? token)
    {
        var parts = MonoText.Split(text);
        Assert.Equal(text, string.Concat(parts.Select(part => part.Text)));
        Assert.All(parts, part => Assert.NotEmpty(part.Text));
        var mono = parts.Where(part => part.Mono).ToArray();
        if (token is null) Assert.Empty(mono);
        else Assert.Equal((token, true), Assert.Single(mono));
        if (text.StartsWith("出口 "))
            Assert.Equal(new[] { ("出口 ", false), ("203.0.113.9", true), (" · 与澳洲节点一致", false) }, parts);
        if (text.EndsWith("/126")) Assert.Equal(("/126", false), parts[^1]);
    }

    [Fact]
    public void 空文字没有片段()
    {
        Assert.Empty(MonoText.Split(null));
        Assert.Empty(MonoText.Split(""));
    }

    [Fact]
    public void 附加属性仅给地址使用等宽资源() => ui.Invoke(() =>
    {
        var text = new TextBlock();
        text.Resources["Yc.Font.Mono"] = new FontFamily("Cascadia Mono, Consolas");
        const string value = "出口 203.0.113.9 · 与澳洲节点一致";
        MonoText.SetText(text, value);
        var runs = text.Inlines.Cast<Run>().ToArray();
        Assert.Equal(3, runs.Length);
        Assert.Equal("203.0.113.9", runs[1].Text);
        Assert.Equal("Cascadia Mono, Consolas", runs[1].FontFamily.Source);
        Assert.NotEqual(runs[1].FontFamily.Source, runs[0].FontFamily.Source);
        Assert.NotEqual(runs[1].FontFamily.Source, runs[2].FontFamily.Source);
        Assert.Equal(value, MonoText.GetText(text));
    });

    [Fact]
    public void 改文字替换旧片段() => ui.Invoke(() =>
    {
        var text = new TextBlock();
        MonoText.SetText(text, "出口 203.0.113.9 · 与澳洲节点一致");
        MonoText.SetText(text, "待检测");
        Assert.Equal("待检测", Assert.IsType<Run>(Assert.Single(text.Inlines.Cast<Inline>())).Text);
        MonoText.SetText(text, null);
        Assert.Empty(text.Inlines.Cast<Inline>());
    });
}
