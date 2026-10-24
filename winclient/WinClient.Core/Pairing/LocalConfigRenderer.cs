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

    // Same key order as the node renderer: password, then obfs (only when set), then tls.
    private static Dictionary<string, object> Backup(NodeInfo node)
    {
        var backup = new Dictionary<string, object>
        {
            ["type"] = "hysteria2", ["tag"] = "backup", ["server"] = node.Host,
            ["server_port"] = node.Hy2Port, ["password"] = node.Hy2Password
        };
        if (!string.IsNullOrEmpty(node.Hy2ObfsPassword))
            backup["obfs"] = new { type = "salamander", password = node.Hy2ObfsPassword };
        backup["tls"] = BackupTls(node);
        return backup;
    }

    public static JsonElement Render(NodeInfo node) => JsonSerializer.SerializeToElement(new
    {
        log = new { disabled = true },
        dns = new
        {
            servers = new[] { new { type = "https", tag = "dns-remote", server = "1.1.1.1", detour = "proxy" } },
            final = "dns-remote", strategy = "ipv4_only"
        },
        inbounds = new[] { new { type = "tun", tag = "tun-in", address = new[] { "172.19.0.1/30", "fdfe:dcba:9876::1/126" },
            auto_route = true, strict_route = true, stack = "system" } },
        outbounds = new object[]
        {
            new { type = "vless", tag = "main", server = node.Host, server_port = node.RealityPort, uuid = node.Uuid,
                flow = "xtls-rprx-vision", tls = new { enabled = true, server_name = node.Sni,
                    utls = new { enabled = true, fingerprint = "chrome" },
                    reality = new { enabled = true, public_key = node.RealityPublicKey, short_id = node.ShortId } } },
            Backup(node),
            new { type = "urltest", tag = "proxy", outbounds = new[] { "main", "backup" },
                url = "https://www.gstatic.com/generate_204", interval = "1m", tolerance = 300 },
        },
        route = new { final = "proxy", rules = new object[] {
            new { action = "sniff" }, new { ip_version = 6, action = "reject" }, new { protocol = "dns", action = "hijack-dns" } }, auto_detect_interface = true }
    });
}
