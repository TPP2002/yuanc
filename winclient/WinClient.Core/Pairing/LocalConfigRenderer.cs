using System.Text.Json;
using WinClient.Core.Auth;

namespace WinClient.Core.Pairing;

public static class LocalConfigRenderer
{
    private static Dictionary<string, object> BackupTls(NodeInfo node)
    {
        var tls = new Dictionary<string, object> { ["enabled"] = true, ["server_name"] = node.Hy2ServerName };
        if (node.Hy2Certificate.Length > 0) tls["certificate"] = node.Hy2Certificate;
        return tls;
    }

    public static JsonElement Render(NodeInfo node) => JsonSerializer.SerializeToElement(new
    {
        log = new { disabled = true },
        dns = new
        {
            servers = new[] { new { tag = "dns-remote", address = "https://1.1.1.1/dns-query", detour = "proxy" } },
            rules = new[] { new { outbound = "any", server = "dns-remote" } },
            final = "dns-remote", strategy = "ipv4_only"
        },
        inbounds = new[] { new { type = "tun", tag = "tun-in", address = new[] { "172.19.0.1/30", "fdfe:dcba:9876::1/126" },
            auto_route = true, strict_route = true, stack = "system", sniff = true } },
        outbounds = new object[]
        {
            new { type = "vless", tag = "main", server = node.Host, server_port = node.RealityPort, uuid = node.Uuid,
                flow = "xtls-rprx-vision", tls = new { enabled = true, server_name = node.Sni,
                    utls = new { enabled = true, fingerprint = "chrome" },
                    reality = new { enabled = true, public_key = node.RealityPublicKey, short_id = node.ShortId } } },
            new { type = "hysteria2", tag = "backup", server = node.Host, server_port = node.Hy2Port,
                password = node.Hy2Password, tls = BackupTls(node) },
            new { type = "urltest", tag = "proxy", outbounds = new[] { "main", "backup" },
                url = "https://www.gstatic.com/generate_204", interval = "1m" },
            new { type = "block", tag = "block" }, new { type = "dns", tag = "dns-out" }
        },
        route = new { final = "proxy", rules = new object[] {
            new { ip_version = 6, outbound = "block" }, new { protocol = "dns", outbound = "dns-out" } }, auto_detect_interface = true }
    });
}
