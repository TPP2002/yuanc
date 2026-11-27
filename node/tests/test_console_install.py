"""管理网页安装准备：放行附加配置、密码与地址清单。"""

import json
from pathlib import Path

from exitnode.config import load
from exitnode.console import install
from exitnode.runner import CompletedResult, FakeRunner

EXAMPLE = (Path(__file__).parents[1] / "examples" / "config.example.toml").read_text(
    encoding="utf-8")
PIN = "A" * 43 + "="


def config_for(*, enabled=False, url="", pin=""):
    text = EXAMPLE.replace(
        '[authsync]\nenabled = false\nurl = ""\nspki_sha256 = ""',
        f'[authsync]\nenabled = {str(enabled).lower()}\nurl = "{url}"\nspki_sha256 = "{pin}"')
    return load("/config", FakeRunner(files={"/config": text}))


def test_extra_allow_only_for_remote_authserver():
    assert install.extra_allow(config_for(enabled=False, url="https://203.0.113.5:8443")) is None
    assert install.extra_allow(config_for(enabled=True, url="http://127.0.0.1:8000")) is None
    assert install.extra_allow(
        config_for(enabled=True, url="https://192.168.1.9:8443", pin=PIN)) is None
    assert install.extra_allow(
        config_for(enabled=True, url="https://203.0.113.5:8443", pin=PIN)) == "203.0.113.5/32"


def test_sync_dropin_writes_only_on_change():
    runner = FakeRunner()
    local = config_for(enabled=False)
    assert install.sync_dropin(local, runner) is True
    assert runner.files[install.DROPIN] == install.dropin_text(local)
    assert "IPAddressAllow" not in runner.files[install.DROPIN]
    writes = sum(call[0] == "write_file" and call[1] == install.DROPIN for call in runner.calls)

    assert install.sync_dropin(local, runner) is False
    assert sum(call[0] == "write_file" and call[1] == install.DROPIN
               for call in runner.calls) == writes

    remote = config_for(enabled=True, url="https://203.0.113.5:8443", pin=PIN)
    assert install.sync_dropin(remote, runner) is True
    assert "IPAddressAllow=203.0.113.5/32" in runner.files[install.DROPIN]

    assert install.sync_dropin(local, runner) is True
    assert "IPAddressAllow" not in runner.files[install.DROPIN]


def test_prepare_generates_password_once_and_empty_admin_key():
    config = config_for(enabled=False)
    runner = FakeRunner()
    password = install.prepare(config, runner)
    assert isinstance(password, str) and password
    assert runner.files[install.PASSWORD].startswith("scrypt$")
    assert runner.modes[install.PASSWORD] == 0o600
    assert runner.files[install.ADMIN_KEY] == ""
    assert runner.modes[install.ADMIN_KEY] == 0o600

    files, modes = dict(runner.files), dict(runner.modes)
    assert install.prepare(config, runner) is None
    assert runner.files == files and runner.modes == modes

    existing = FakeRunner(files={install.ADMIN_KEY: "test-admin-only"})
    assert install.prepare(config, existing) is not None
    assert existing.files[install.ADMIN_KEY] == "test-admin-only"


def test_urls_lan_and_tunnel():
    runner = FakeRunner(responses={
        ("ip", "-j", "route"): CompletedResult(out='[{"dst":"default","dev":"eth0"}]'),
        ("ip", "-j", "addr"): CompletedResult(out=json.dumps([
            {"ifname": "eth0", "ifindex": 2, "flags": ["UP"],
             "addr_info": [{"family": "inet", "scope": "global", "local": "192.0.2.2"}]}])),
    })
    config = config_for(enabled=True, url="http://127.0.0.1:8000")
    assert config.console.enabled and config.console.lan
    assert install.urls(config, runner) == ["http://192.0.2.2:8444/", "http://198.18.255.2/"]

    config.console.lan = False
    assert install.urls(config, runner) == ["http://198.18.255.2/"]

    config.console.lan = True
    broken = FakeRunner(responses={("ip", "-j", "route"): CompletedResult(1)})
    assert install.urls(config, broken) == ["http://198.18.255.2/"]
