from pathlib import Path

import pytest
from exitnode.config import ConfigError, load
from exitnode.runner import FakeRunner

EXAMPLE = Path(__file__).parents[1] / "examples" / "config.example.toml"


def test_authsync_defaults_disabled():
    text = EXAMPLE.read_text(encoding="utf-8")
    for source in (text, text.split("[authsync]")[0]):
        value = load("/config", FakeRunner(files={"/config": source})).authsync
        assert not value.enabled and value.url == value.spki_sha256 == ""


@pytest.mark.parametrize("url,pin,extra,valid", [
    ("", "", "", False),
    ("http://example.com", "", "", False),
    ("https://example.com", "", "", False),
    ("http://127.0.0.1", "A" * 43 + "=", "", False),
    ("https://example.com/path", "A" * 43 + "=", "", False),
    ("https://example.com", "bad", "", False),
    ("http://127.0.0.1", "", "unknown = true\n", False),
    ("http://127.0.0.1:8000", "", "", True),
    ("https://example.com:443", "A" * 43 + "=", "", True),
])
def test_authsync_validation(url, pin, extra, valid):
    text = EXAMPLE.read_text(encoding="utf-8").split("[authsync]")[0]
    text += f'[authsync]\nenabled = true\nurl = "{url}"\nspki_sha256 = "{pin}"\n{extra}'
    runner = FakeRunner(files={"/config": text})
    if valid:
        assert load("/config", runner).authsync.enabled
    else:
        with pytest.raises(ConfigError, match="authsync"):
            load("/config", runner)


def environment_config(**values):
    text = EXAMPLE.read_text(encoding="utf-8")
    text = "\n".join(line for line in text.splitlines()
                     if not line.startswith(("time_zone =", "country =")))
    fields = "\n".join(f'{key} = "{value}"' for key, value in values.items())
    return text.replace("[node]", "[node]\n" + fields)


@pytest.mark.parametrize("values", [{}, {"time_zone": "", "country": ""}])
def test_node_environment_defaults_empty(values):
    config = load("/config", FakeRunner(files={"/config": environment_config(**values)}))
    assert config.node.time_zone == ""
    assert config.node.country == ""


@pytest.mark.parametrize("zone", ["Australia/Perth", "W. Australia Standard Time"])
def test_node_environment_accepts_valid_fields(zone):
    text = environment_config(time_zone=zone, country="AU")
    config = load("/config", FakeRunner(files={"/config": text}))
    assert config.node.time_zone == zone
    assert config.node.country == "AU"


@pytest.mark.parametrize("field,value,reason", [
    ("time_zone", "bad;zone", "须为 IANA 时区名"),
    ("time_zone", "a" * 65, "须为 IANA 时区名"),
    ("time_zone", r"Australia/Perth\n", "须为 IANA 时区名"),
    ("country", "au", "须为两位大写国家码"),
    ("country", "AUS", "须为两位大写国家码"),
    ("country", r"AU\n", "须为两位大写国家码"),
])
def test_node_environment_rejects_invalid_fields(field, value, reason):
    text = environment_config(**{field: value})
    with pytest.raises(ConfigError, match=f"node.{field}.*{reason}"):
        load("/config", FakeRunner(files={"/config": text}))


def test_example_and_default_secret_path():
    text = EXAMPLE.read_text(encoding="utf-8")
    text = text.replace('secrets_dir = "/var/lib/exitnode/secrets"\n', "")
    config = load("/config.toml", FakeRunner(files={"/config.toml": text}))
    assert config.node.secrets_dir == "/var/lib/exitnode/secrets"
    assert config.network.iface == "auto"
    assert config.proxy.reality_port == 443


@pytest.mark.parametrize("old,new,key,reason", [
    ('name = "请填写节点名称"', "", "node.name", "缺少"),
    ('hy2_port = 24443', 'hy2_port = "24443"', "proxy.hy2_port", "类型"),
    ('hy2_port = 24443', 'hy2_port = true', "proxy.hy2_port", "类型"),
    ('name = "请填写节点名称"', 'typo = "x"', "node.typo", "未知"),
    ('mode = "upnp"', 'mode = "other"', "publisher.mode", "只支持"),
    ('port = 8443', 'port = 0', "admin.port", "端口"),
    ('probe_targets = ["1.1.1.1", "8.8.8.8"]', 'probe_targets = []',
     "network.probe_targets", "类型"),
    ('secrets_dir = "/var/lib/exitnode/secrets"', 'secrets_dir = "/tmp/keys"',
     "node.secrets_dir", "凭据"),
])
def test_invalid_fields_are_chinese_and_located(old, new, key, reason):
    text = EXAMPLE.read_text(encoding="utf-8").replace(old, new)
    with pytest.raises(ConfigError) as error:
        load("/config.toml", FakeRunner(files={"/config.toml": text}))
    assert "/config.toml" in str(error.value)
    assert key in str(error.value)
    assert reason in str(error.value)


def test_invalid_toml_does_not_echo_secret():
    with pytest.raises(ConfigError) as error:
        load("/config.toml", FakeRunner(files={"/config.toml": 'token = "PRIVATE\n'}))
    assert "PRIVATE" not in str(error.value)
    assert "格式" in str(error.value)


def test_proxy_defaults():
    text = EXAMPLE.read_text(encoding="utf-8")
    for name, value in (("hy2_server_name", "exitnode"), ("binary", "/usr/bin/sing-box")):
        text = text.replace(f'{name} = "{value}"\n', "")
    proxy = load("/config", FakeRunner(files={"/config": text})).proxy
    assert proxy.sni == proxy.handshake_server == "www.abc.net.au"
    assert proxy.hy2_server_name == "exitnode"
    assert proxy.binary == "/opt/exitnode/current/bin/sing-box"


@pytest.mark.parametrize("field", ["sni", "handshake_server"])
def test_camouflage_target_is_required_without_default(field):
    text = EXAMPLE.read_text(encoding="utf-8")
    text = "\n".join(line for line in text.splitlines() if not line.startswith(field + " ="))
    with pytest.raises(ConfigError, match=f"proxy.{field}.*缺少必填字段"):
        load("/config", FakeRunner(files={"/config": text}))


def test_camouflage_target_must_match():
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        'handshake_server = "www.abc.net.au"', 'handshake_server = "www.example.com.au"')
    with pytest.raises(ConfigError, match="必须与 proxy.sni 相同"):
        load("/config", FakeRunner(files={"/config": text}))


def test_camouflage_target_accepts_matching_non_microsoft_name():
    text = EXAMPLE.read_text(encoding="utf-8").replace("www.abc.net.au", "www.example.com.au")
    proxy = load("/config", FakeRunner(files={"/config": text})).proxy
    assert proxy.sni == proxy.handshake_server == "www.example.com.au"


@pytest.mark.parametrize("old,new,key", [
    ('releases_dir = "/opt/exitnode"', 'releases_dir = "/srv/exitnode"', "updater.releases_dir"),
    ('data_dir = "/var/lib/exitnode"', 'data_dir = "/var/lib/other"', "node.data_dir"),
])
def test_layout_paths_are_locked(old, new, key):
    text = EXAMPLE.read_text(encoding="utf-8").replace(old, new)
    with pytest.raises(ConfigError, match=f"{key}.*固定布局"):
        load("/config", FakeRunner(files={"/config": text}))


def test_layout_defaults_pass():
    config = load("/config", FakeRunner(files={"/config": EXAMPLE.read_text(encoding="utf-8")}))
    assert config.node.data_dir == "/var/lib/exitnode"
    assert config.updater.releases_dir == "/opt/exitnode"


@pytest.mark.parametrize("field,value", [
    ("sni", '"bad/name"'), ("sni", '"-bad.example"'), ("sni", '"a..b"'),
    ("handshake_server", '"bad name"'), ("hy2_server_name", '"bad/name"'),
    ("sni", "12"), ("binary", "false"), ("binary", '"relative"'),
    ("binary", '"/usr/../bin/sing-box"'), ("binary", '"/usr/bin/$bad"'),
    ("unknown", '"value"'),
])
def test_proxy_strict_fields(field, value):
    text = EXAMPLE.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith(field + " =")]
    text = "\n".join(lines).replace("[proxy]", f"[proxy]\n{field} = {value}")
    with pytest.raises(ConfigError, match="proxy." + field):
        load("/config", FakeRunner(files={"/config": text}))


def test_watchdog_defaults_and_example():
    from dataclasses import asdict

    from exitnode.config import Watchdog
    text = EXAMPLE.read_text(encoding="utf-8")
    for source in (text, text.split("[watchdog]")[0]):
        value = load("/config", FakeRunner(files={"/config": source})).watchdog
        assert asdict(value) == asdict(Watchdog())
        assert value.enabled and value.hardware and value.reboot_enabled
        assert not value.weekly_reboot
        assert value.restart_limit_per_hour == 3
        assert value.rollback_min_interval_hours == value.reboot_min_interval_hours == 6
        assert value.reboot_after_minutes == 30


@pytest.mark.parametrize("key,value", [
    ("restart_limit_per_hour", "-1"), ("rollback_min_interval_hours", "-1"),
    ("reboot_min_interval_hours", "-1"), ("reboot_after_minutes", "4"),
    ("reboot_after_minutes", "-1"), ("enabled", "1"), ("hardware", '"true"'),
    ("weekly_reboot", "0"), ("reboot_enabled", "1"), ("unknown", "true"),
    ("restart_after_failures", "3"), ("retry_interval_seconds", "0"),
    ("max_backoff_seconds", "30"),
])
def test_watchdog_rejects_invalid_values(key, value):
    text = EXAMPLE.read_text(encoding="utf-8").split("[watchdog]")[0]
    text += f"[watchdog]\n{key} = {value}\n"
    with pytest.raises(ConfigError, match="watchdog." + key):
        load("/config", FakeRunner(files={"/config": text}))


def test_updater_defaults_and_legacy_config_version():
    text = EXAMPLE.read_text(encoding="utf-8")
    for line in ('config_version = 1\n', 'source = "none"\n', 'github_repo = ""\n',
                 'health_timeout_sec = 120\n', 'releases_dir = "/opt/exitnode"\n'):
        text = text.replace(line, "")
    config = load("/config", FakeRunner(files={"/config": text}))
    assert config.node.config_version == 1
    assert config.updater.source == "none" and config.updater.github_repo == ""
    assert config.updater.health_timeout_sec == 120
    assert config.updater.releases_dir == "/opt/exitnode"


@pytest.mark.parametrize("value", ["0", "-1", '"1"', "true", "1.5"])
def test_config_version_must_be_positive_integer(value):
    text = EXAMPLE.read_text(encoding="utf-8").replace("config_version = 1", "config_version = " + value)
    with pytest.raises(ConfigError, match="node.config_version.*须为正整数"):
        load("/config", FakeRunner(files={"/config": text}))


@pytest.mark.parametrize("key,value", [("source", '"other"'), ("source", "1"),
                                      ("github_repo", '"https://bad/repo"'),
                                      ("health_timeout_sec", "0"),
                                      ("health_timeout_sec", "true"),
                                      ("releases_dir", '"/"'),
                                      ("releases_dir", '"/opt/../etc"')])
def test_updater_invalid_values(key, value):
    text = EXAMPLE.read_text(encoding="utf-8")
    text = "\n".join(line for line in text.splitlines() if not line.startswith(key + " ="))
    text = text.replace("[updater]", f"[updater]\n{key} = {value}")
    with pytest.raises(ConfigError, match="updater." + key):
        load("/config", FakeRunner(files={"/config": text}))


def test_health_stable_sec_default_and_zero():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert load("/config", FakeRunner(files={"/config": text})).updater.health_stable_sec == 30
    text = text.replace("[updater]", "[updater]\nhealth_stable_sec = 0")
    assert load("/config", FakeRunner(files={"/config": text})).updater.health_stable_sec == 0


@pytest.mark.parametrize("value", ["-1", "true", '"30"', "1.5"])
def test_health_stable_sec_must_be_non_negative_integer(value):
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "[updater]", f"[updater]\nhealth_stable_sec = {value}")
    with pytest.raises(ConfigError, match="updater.health_stable_sec.*须为非负整数秒数"):
        load("/config", FakeRunner(files={"/config": text}))


def test_github_source_requires_repository():
    text = EXAMPLE.read_text(encoding="utf-8").replace('source = "none"', 'source = "github"')
    with pytest.raises(ConfigError, match="github_repo"):
        load("/config", FakeRunner(files={"/config": text}))


def test_maintenance_devices_default_empty():
    text = EXAMPLE.read_text(encoding="utf-8")
    config = load("/config", FakeRunner(files={"/config": text}))
    assert config.proxy.maintenance_device_ids == []


@pytest.mark.parametrize("value,expected", [('[]', []), ('["dev-b", "dev-a"]', ["dev-b", "dev-a"])])
def test_maintenance_device_list_loaded(value, expected):
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "[proxy]", f"[proxy]\nmaintenance_device_ids = {value}")
    config = load("/config", FakeRunner(files={"/config": text}))
    assert config.proxy.maintenance_device_ids == expected


@pytest.mark.parametrize("value", ['"device"', '22', 'true', '{}', '[22]', '["dev", false]'])
def test_maintenance_device_list_rejects_wrong_types(value):
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "[proxy]", f"[proxy]\nmaintenance_device_ids = {value}")
    with pytest.raises(ConfigError, match="proxy.maintenance_device_ids.*类型"):
        load("/config", FakeRunner(files={"/config": text}))


def test_console_section_defaults_and_validation():
    text = EXAMPLE.read_text(encoding="utf-8")
    console = load("/config", FakeRunner(files={"/config": text})).console
    assert (console.enabled, console.port, console.lan) == (False, 8444, True)

    for port in (80, 70000):
        changed = text + f"\n[console]\nport = {port}\n"
        with pytest.raises(ConfigError, match="console.port.*1024 至 65535"):
            load("/config", FakeRunner(files={"/config": changed}))

    # 与 admin.port 相同也算冲突（示例里 admin.port 是 8443）。
    same = text + "\n[console]\nport = 8443\n"
    with pytest.raises(ConfigError, match="console.port.*不能与"):
        load("/config", FakeRunner(files={"/config": same}))

    enabled = text + "\n[console]\nenabled = true\nlan = false\nport = 9444\n"
    value = load("/config", FakeRunner(files={"/config": enabled})).console
    assert value.enabled is True and value.lan is False and value.port == 9444
