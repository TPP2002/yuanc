using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Network;

namespace WinClient.Core.Diagnostics;

public sealed record ReachTarget(string Host, int Port, string ServerName);

public sealed record ReachResult(string? Json, string? Error);

/// <summary>从物理网卡直连目标端口做一次 TCP 连接与一次标准 TLS 握手，握手完立刻关闭，不传应用数据。</summary>
public static class ReachProbe
{
    public static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(4);
    public static readonly ReachTarget Ipv6Target = new("2606:4700:4700::1111", 443, "one.one.one.one");
    public const string NoTarget = "直连握手探测没有做：后台服务这次启动以来还没有连接过，没有可测的目标。";

    /// <summary>从内核配置里取主通道目标；配置不合要求时返回 null，不抛异常。</summary>
    public static ReachTarget? MainTargetFrom(JsonElement configuration)
    {
        try
        {
            if (configuration.ValueKind != JsonValueKind.Object) return null;
            if (!configuration.TryGetProperty("outbounds", out var outbounds) || outbounds.ValueKind != JsonValueKind.Array)
                return null;
            foreach (var outbound in outbounds.EnumerateArray())
            {
                if (outbound.ValueKind != JsonValueKind.Object) continue;
                if (!outbound.TryGetProperty("tag", out var tag) || tag.ValueKind != JsonValueKind.String ||
                    tag.GetString() != "main") continue;
                if (!outbound.TryGetProperty("server", out var server) || server.ValueKind != JsonValueKind.String) return null;
                var host = server.GetString();
                if (string.IsNullOrEmpty(host)) return null;
                if (!outbound.TryGetProperty("server_port", out var portElement) || portElement.ValueKind != JsonValueKind.Number ||
                    !portElement.TryGetInt32(out var port) || port < 1 || port > 65535) return null;
                if (!outbound.TryGetProperty("tls", out var tls) || tls.ValueKind != JsonValueKind.Object) return null;
                if (!tls.TryGetProperty("server_name", out var serverName) || serverName.ValueKind != JsonValueKind.String)
                    return null;
                var name = serverName.GetString();
                if (string.IsNullOrEmpty(name)) return null;
                return new ReachTarget(host, port, name);
            }
            return null;
        }
        catch (Exception) { return null; }
    }

    public static async Task<ReachResult> RunAsync(ReachTarget? target, bool bindPhysical, TimeSpan? stepTimeout = null, CancellationToken token = default)
    {
        if (target is null) return new(null, NoTarget);
        token.ThrowIfCancellationRequested();
        var step = stepTimeout ?? StepTimeout;
        var bound = false;
        var tcp = "failed";
        int tcpMs = 0;
        Socket? socket = null;
        string? tls = null;
        string? tlsProtocol = null;
        string? certErrors = null;
        string? certIssuer = null;
        int? tlsMs = null;
        try
        {
            var tcpWatch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using var tcpSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                tcpSource.CancelAfter(step);
                IPAddress? address = IPAddress.TryParse(target.Host, out var parsed) ? parsed : null;
                if (address is null)
                {
                    var resolved = await Dns.GetHostAddressesAsync(target.Host).WaitAsync(tcpSource.Token).ConfigureAwait(false);
                    address = resolved.FirstOrDefault(item => item.AddressFamily == AddressFamily.InterNetwork)
                        ?? resolved.FirstOrDefault();
                }
                if (address is null)
                {
                    tcp = "failed";
                }
                else
                {
                    socket = address.AddressFamily == AddressFamily.InterNetworkV6
                        ? new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp)
                        : new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    if (bindPhysical && address.AddressFamily == AddressFamily.InterNetwork &&
                        DefaultRouteBinding.Pick(DefaultRouteBinding.ReadSystem(), NetworkInterface.LoopbackInterfaceIndex) is { } index)
                    {
                        socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder(index));
                        bound = true;
                    }
                    await socket.ConnectAsync(new IPEndPoint(address, target.Port), tcpSource.Token).ConfigureAwait(false);
                    tcp = "ok";
                }
            }
            catch (OperationCanceledException)
            {
                if (token.IsCancellationRequested) throw;
                tcp = "timeout";
            }
            catch (SocketException ex)
            {
                tcp = ex.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => "refused",
                    SocketError.ConnectionReset or SocketError.ConnectionAborted => "reset",
                    SocketError.NetworkUnreachable or SocketError.HostUnreachable => "unreachable",
                    SocketError.TimedOut => "timeout",
                    _ => "failed"
                };
            }
            catch (Exception) { tcp = "failed"; }
            tcpWatch.Stop();
            tcpMs = (int)tcpWatch.ElapsedMilliseconds;

            if (tcp == "ok")
            {
                var network = new NetworkStream(socket!, ownsSocket: true);
                socket = null;
                var tlsWatch = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    using var tlsSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                    tlsSource.CancelAfter(step);
                    RemoteCertificateValidationCallback validation = (object? sender, X509Certificate? certificate,
                        X509Chain? chain, SslPolicyErrors errors) =>
                    {
                        certErrors = errors.ToString();
                        var issuer = certificate?.Issuer ?? "";
                        certIssuer = issuer.Length > 200 ? issuer[..200] : issuer;
                        return true;
                    };
                    using var ssl = new SslStream(network, leaveInnerStreamOpen: false, validation);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = target.ServerName },
                        tlsSource.Token).ConfigureAwait(false);
                    tls = "ok";
                    tlsProtocol = ssl.SslProtocol.ToString();
                }
                catch (OperationCanceledException)
                {
                    if (token.IsCancellationRequested) throw;
                    tls = "timeout";
                }
                catch (IOException ex) when (HasSocketReset(ex))
                {
                    tls = "reset";
                }
                catch (IOException)
                {
                    tls = "closed";
                }
                catch (Exception)
                {
                    tls = "failed";
                }
                finally
                {
                    tlsWatch.Stop();
                    tlsMs = (int)tlsWatch.ElapsedMilliseconds;
                }
            }
        }
        finally
        {
            socket?.Dispose();
        }
        if (tls != "ok")
        {
            tlsProtocol = null;
            certErrors = null;
            certIssuer = null;
        }
        var json = new JsonObject
        {
            ["bound"] = bound,
            ["tcp"] = tcp,
            ["tcp_ms"] = tcpMs,
            ["tls"] = tls,
            ["tls_ms"] = tlsMs,
            ["tls_protocol"] = tlsProtocol,
            ["cert_errors"] = certErrors,
            ["cert_issuer"] = certIssuer
        };
        return new(json.ToJsonString(), null);
    }

    private static bool HasSocketReset(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is SocketException socket &&
                (socket.SocketErrorCode == SocketError.ConnectionReset || socket.SocketErrorCode == SocketError.ConnectionAborted))
                return true;
        }
        return false;
    }
}
