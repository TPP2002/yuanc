from pathlib import Path

import pytest
from exitnode.config import ConfigError, load
from exitnode.runner import FakeRunner

EXAMPLE = Path(__file__).parents[1] / "examples" / "config.example.toml"


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
    for name, value in (("sni", "www.microsoft.com"),
                        ("handshake_server", "www.microsoft.com"),
                        ("hy2_server_name", "exitnode"), ("binary", "/usr/bin/sing-box")):
        text = text.replace(f'{name} = "{value}"\n', "")
    proxy = load("/config", FakeRunner(files={"/config": text})).proxy
    assert proxy.sni == proxy.handshake_server == "www.microsoft.com"
    assert proxy.hy2_server_name == "exitnode"
    assert proxy.binary == "/usr/bin/sing-box"


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
