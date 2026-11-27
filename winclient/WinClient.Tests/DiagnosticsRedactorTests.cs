using System.Text.Json;
using WinClient.Core.Diagnostics;
using Xunit;

namespace WinClient.Tests;

public class DiagnosticsRedactorTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    public void PublicIpv4IsMaskedAndPrivateKept(string address)
    {
        var redacted = DiagnosticsRedactor.RedactStructured($"服务器看到 {address} 这个地址");
        Assert.Contains(DiagnosticsRedactor.PublicAddressMark, redacted);
        Assert.Equal("[公网地址]", DiagnosticsRedactor.RedactStructured(address));
        Assert.DoesNotContain(address, redacted);
        foreach (var kept in new[] { "192.168.1.52", "10.0.0.2", "198.18.255.1", "127.0.0.1" })
            Assert.Equal(kept, DiagnosticsRedactor.RedactStructured(kept));
    }

    [Theory]
    [InlineData("2404:6800:4006:80a::200e")]
    public void PublicIpv6IsMaskedAndLocalKept(string address)
    {
        var redacted = DiagnosticsRedactor.RedactStructured($"节点地址 {address} 结束");
        Assert.Contains(DiagnosticsRedactor.PublicAddressMark, redacted);
        Assert.DoesNotContain(address, redacted);
        foreach (var kept in new[] { "fe80::1c2d:3e4f:5a6b:7c8d", "2001:db8::1" })
            Assert.Equal(kept, DiagnosticsRedactor.RedactStructured(kept));
    }

    [Fact]
    public void TimestampsAndVersionsAreNotTouched()
    {
        const string text = "2026-11-28T01:02:03.1234567+00:00 版本 0.1.2 系统 10.0.19045";
        Assert.Equal(text, DiagnosticsRedactor.RedactStructured(text));
    }

    [Fact]
    public void UserDirectoryIsMaskedInPlainAndJsonEscapedPaths()
    {
        Assert.Equal(@"C:\Users\[用户]\AppData\x.exe",
            DiagnosticsRedactor.Redact(@"C:\Users\alice\AppData\x.exe"));
        Assert.Equal(@"C:\\Users\\[用户]\\AppData",
            DiagnosticsRedactor.RedactStructured(@"C:\\Users\\alice\\AppData"));
        Assert.DoesNotContain("alice", DiagnosticsRedactor.Redact(@"C:\Users\alice\AppData\x.exe"));
    }

    [Fact]
    public void LabelledSecretsAndBearerAreHidden()
    {
        var redacted = DiagnosticsRedactor.Redact("token=abc123 Authorization: Bearer xyz789");
        Assert.Contains("[已隐藏]", redacted);
        Assert.DoesNotContain("abc123", redacted);
        Assert.DoesNotContain("xyz789", redacted);
    }

    [Fact]
    public void NullAndEmptyBecomeEmpty()
    {
        Assert.Equal("", DiagnosticsRedactor.RedactStructured(null));
        Assert.Equal("", DiagnosticsRedactor.RedactStructured(""));
        Assert.Equal("", DiagnosticsRedactor.Redact(null));
        Assert.Equal("", DiagnosticsRedactor.Redact(""));
    }

    [Fact]
    public void RedactStructuredKeepsJsonValid()
    {
        const string json = "{\"ip\":\"8.8.8.8\",\"path\":\"C:\\\\Users\\\\alice\\\\app.exe\"}";
        var redacted = DiagnosticsRedactor.RedactStructured(json);
        using var document = JsonDocument.Parse(redacted);
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }
}
