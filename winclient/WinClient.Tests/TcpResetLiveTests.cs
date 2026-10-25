using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using WinClient.Core.Network;
using Xunit;

namespace WinClient.Tests;

/// <summary>真机测试:只在本机回环上自建一对连接并重置它,不碰任何其他连接。</summary>
[Collection("WFP live serial")]
[SupportedOSPlatform("windows")]
public sealed class TcpResetLiveTests
{
    [WfpLiveFact]
    public async Task ResetClosesLoopbackConnection()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var client = new TcpClient();
        var accepting = listener.AcceptTcpClientAsync();
        await client.ConnectAsync(IPAddress.Loopback, serverPort);
        using var server = await accepting;
        var clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        var table = new SystemTcpTable();
        var entry = table.Snapshot().Single(e => e.LocalPort == clientPort && e.RemotePort == serverPort
            && IPAddress.IsLoopback(e.Local) && IPAddress.IsLoopback(e.Remote));
        Assert.True(table.Reset(entry));

        var buffer = new byte[16];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            var read = await server.GetStream().ReadAsync(buffer, timeout.Token);
            Assert.Equal(0, read);
        }
        catch (IOException) { /* 对端读到连接重置,符合预期。 */ }
    }
}
