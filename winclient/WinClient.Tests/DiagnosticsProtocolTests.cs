using WinClient.Core.Ipc;
using Xunit;

namespace WinClient.Tests;

public class DiagnosticsProtocolTests
{
    [Fact]
    public void ResponseCarriesDiagnosticsField()
    {
        var line = ControlProtocol.Encode(new ControlResponse(1, true, Diagnostics: "{\"a\":1}"));
        Assert.Contains("diagnostics", line);
        var decoded = ControlProtocol.DecodeResponse(line.Trim());
        Assert.Equal("{\"a\":1}", decoded.Diagnostics);
    }

    [Fact]
    public void OldResponseWithoutFieldDecodesToNull()
    {
        var decoded = ControlProtocol.DecodeResponse("{\"id\":1,\"ok\":true}");
        Assert.Null(decoded.Diagnostics);
    }
}
