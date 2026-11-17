from pathlib import Path

import pytest
from exitnode.systemd import render

UNITS = ("exitnode-admin.service", "exitnode-proxy.service",
         "exitnode-publisher.service", "exitnode-publisher.timer",
         "exitnode-authsync.service", "exitnode-authsync.timer",
         "exitnode-watchdog.service", "exitnode-watchdog.timer",
         "exitnode-recover.service", "exitnode-nft.service")
NFT_UNIT = "exitnode-nft.service"


@pytest.mark.parametrize("name", UNITS)
def test_unit_matches_golden(name):
    text = render(name, {})
    assert text == (Path(__file__).parent / "golden" / name).read_text(encoding="utf-8")
    if name.startswith(("exitnode-admin.service", "exitnode-proxy.service")):
        assert "StartLimitIntervalSec=" in text
        assert "StartLimitBurst=" in text
    else:
        assert "StartLimit" not in text
    # 防火墙规则单元不是 python 程序，也不需要重启策略。
    if name.endswith(".service") and name != NFT_UNIT:
        assert "Restart=" in text
        assert "Environment=PYTHONPATH=/opt/exitnode/current\n" in text
    if name == NFT_UNIT:
        assert "Environment=PYTHONPATH" not in text
        assert "Restart=" not in text


def test_proxy_runs_as_service_account_with_only_bind_capability():
    proxy = render("exitnode-proxy.service", {})
    for line in ("User=exitnode", "Group=exitnode", "AmbientCapabilities=CAP_NET_BIND_SERVICE",
                 "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "NoNewPrivileges=true",
                 "ProtectSystem=strict", "ReadOnlyPaths=/var/lib/exitnode/secrets",
                 "SystemCallFilter=@system-service", "ProtectProc=invisible"):
        assert line + "\n" in proxy
    assert "DynamicUser" not in proxy
    assert "After=network-online.target exitnode-nft.service\n" in proxy


def test_admin_uses_dynamic_user_without_capabilities_and_only_localhost():
    admin = render("exitnode-admin.service", {})
    for line in ("DynamicUser=true", "IPAddressDeny=any", "IPAddressAllow=localhost",
                 "CapabilityBoundingSet=", "ProtectSystem=strict",
                 "RestrictAddressFamilies=AF_INET AF_INET6",
                 "ReadOnlyPaths=-/var/lib/exitnode/winclient",
                 "TasksMax=64", "LimitNOFILE=1024", "MemoryMax=256M"):
        assert line + "\n" in admin
    assert "\nUser=" not in admin
    # 发布目录首次发布前不存在:带 - 前缀才会跳过,否则单元以 226/NAMESPACE 起不来。
    assert [line for line in admin.splitlines() if line.startswith("ReadOnlyPaths=")] == [
        "ReadOnlyPaths=-/var/lib/exitnode/winclient"]


@pytest.mark.parametrize("name", ["exitnode-watchdog.service", "exitnode-recover.service",
                                  "exitnode-rescue.service", "exitnode-authsync.service"])
def test_root_units_are_sandboxed_but_keep_root(name):
    text = render(name, {})
    assert "ProtectSystem=full\n" in text and "ProtectHome=true\n" in text
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n" in text
    assert "/usr/bin/python3 -P -m " in text
    assert "\nUser=" not in text and "DynamicUser" not in text
    assert "CapabilityBoundingSet" not in text


def test_nft_unit_reloads_rule_file_before_proxy():
    text = render(NFT_UNIT, {})
    assert "Type=oneshot\n" in text and "RemainAfterExit=yes\n" in text
    assert "ConditionPathExists=/var/lib/exitnode/exitnode.nft\n" in text
    assert "ExecStart=/usr/sbin/nft -f /var/lib/exitnode/exitnode.nft\n" in text
    assert "Before=network-pre.target exitnode-proxy.service\n" in text
    assert "DefaultDependencies=no\n" in text
    assert "WantedBy=multi-user.target\n" in text


def test_admin_and_proxy_have_independent_entrypoints():
    admin, proxy = render(UNITS[0], {}), render(UNITS[1], {})
    assert admin != proxy
    assert ('ExecStart=/usr/bin/python3 -P -m exitnode --config "/etc/exitnode/config.toml"'
            ' admin serve\n') in admin
    assert "ExecStart=/opt/exitnode/current/bin/sing-box run -c /var/lib/exitnode/secrets/sing-box.json\n" in proxy
    assert "Restart=always\n" in proxy
    assert "RestartSec=3\n" in proxy
    assert "ExecReload=/bin/kill -HUP $MAINPID\n" in proxy
    assert "After=network-online.target exitnode-nft.service\n" in proxy
    assert "--placeholder proxy" not in proxy
    assert "exitnode-proxy.service" not in admin


def test_template_context_cannot_inject_directives():
    with pytest.raises(ValueError):
        render(UNITS[0], {"config_path": "/a\nExecStart=/bin/other"})


def test_proxy_binary_override():
    text = render("exitnode-proxy.service", {}, binary="/opt/sing-box")
    assert "ExecStart=/opt/sing-box run -c /var/lib/exitnode/secrets/sing-box.json\n" in text
    with pytest.raises(ValueError):
        render("exitnode-proxy.service", {}, binary="/a\nExecStart=/bin/other")


def test_watchdog_service_timer_and_context():
    text = render("exitnode-watchdog.service", {"config_path": "/etc/custom config.toml"})
    assert 'ExecStart=/usr/bin/python3 -P -m exitnode --config "/etc/custom config.toml" watchdog tick\n' in text
    assert "Type=oneshot\n" in text
    timer = render("exitnode-watchdog.timer", {})
    assert "StartLimit" not in text
    assert "StartLimit" not in timer
    assert "OnBootSec=90\n" in timer
    assert "OnUnitActiveSec=60\n" in timer
    assert "Persistent=false\n" in timer
    for unsafe in ('/a\nExecStart=/bin/other', '/a"', '/%n', '/$HOME', '/a\\b'):
        with pytest.raises(ValueError):
            render("exitnode-watchdog.service", {"config_path": unsafe})


def test_authsync_service_and_timer():
    text = render("exitnode-authsync.service", {})
    assert ' --config "/etc/exitnode/config.toml" authsync tick\n' in text
    assert "Type=oneshot\n" in text
    timer = render("exitnode-authsync.timer", {})
    assert "OnBootSec=60\n" in timer and "OnUnitActiveSec=60\n" in timer


def test_publisher_service_and_timer():
    text = render("exitnode-publisher.service", {})
    assert ' --config "/etc/exitnode/config.toml" publisher tick\n' in text
    assert "Type=oneshot\n" in text
    timer = render("exitnode-publisher.timer", {})
    assert "OnBootSec=45\n" in timer and "OnUnitActiveSec=600\n" in timer


def test_recover_unit_runs_once_after_proxy_on_boot():
    text = render("exitnode-recover.service", {"config_path": "/etc/custom config.toml",
                                               "program_path": "/srv/exitnode/current"})
    assert "Type=oneshot\n" in text and "Restart=no\n" in text
    assert "After=network-online.target exitnode-proxy.service\n" in text
    assert 'ExecStart=/usr/bin/python3 -P -m exitnode --config "/etc/custom config.toml" upgrade --recover\n' in text
    assert "Environment=PYTHONPATH=/srv/exitnode/current\n" in text
    assert "WantedBy=multi-user.target\n" in text
    assert "StartLimit" not in text


@pytest.mark.parametrize("name", ["exitnode-rescue.service", "exitnode-rescue.timer"])
def test_rescue_unit_matches_golden(name):
    text = render(name, {})
    assert text == (Path(__file__).parent / "golden" / name).read_text(encoding="utf-8")
    if name.endswith(".service"):
        assert "Type=oneshot\n" in text
        assert "Environment=PYTHONPATH=/opt/exitnode-rescue\n" in text
        assert "ExecStart=/usr/bin/python3 -P -m exitnode_rescue tick\n" in text
        assert "NoNewPrivileges=true\n" in text and "UMask=0077\n" in text
        assert "/opt/exitnode/current" not in text
    else:
        assert "OnBootSec=180\n" in text
        assert "OnUnitActiveSec=300\n" in text
        assert "Persistent=false\n" in text
