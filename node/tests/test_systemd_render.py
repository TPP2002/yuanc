from pathlib import Path

import pytest
from exitnode.systemd import render

UNITS = ("exitnode-admin.service", "exitnode-proxy.service",
         "exitnode-watchdog.service", "exitnode-watchdog.timer")


@pytest.mark.parametrize("name", UNITS)
def test_unit_matches_golden(name):
    text = render(name, {})
    assert text == (Path(__file__).parent / "golden" / name).read_text(encoding="utf-8")
    assert "StartLimitIntervalSec=" in text
    assert "StartLimitBurst=" in text
    if name.endswith(".service"):
        assert "Restart=" in text


def test_admin_and_proxy_have_independent_entrypoints():
    admin, proxy = render(UNITS[0], {}), render(UNITS[1], {})
    assert admin != proxy
    assert "--placeholder admin" in admin
    assert "ExecStart=/usr/bin/sing-box run -c /var/lib/exitnode/secrets/sing-box.json\n" in proxy
    assert "Restart=always\n" in proxy
    assert "RestartSec=3\n" in proxy
    assert "ExecReload=/bin/kill -HUP $MAINPID\n" in proxy
    assert "After=network-online.target\n" in proxy
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
    assert 'ExecStart=/usr/bin/python3 -m exitnode --config "/etc/custom config.toml" watchdog tick\n' in text
    assert "Type=oneshot\n" in text
    timer = render("exitnode-watchdog.timer", {})
    assert "OnBootSec=90\n" in timer
    assert "OnUnitActiveSec=60\n" in timer
    assert "Persistent=false\n" in timer
    for unsafe in ('/a\nExecStart=/bin/other', '/a"', '/%n', '/$HOME', '/a\\b'):
        with pytest.raises(ValueError):
            render("exitnode-watchdog.service", {"config_path": unsafe})
