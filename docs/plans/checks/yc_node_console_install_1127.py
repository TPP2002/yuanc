"""安装单 yc-node-console-install-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / "node"
TEMPLATES = NODE / "exitnode/templates"
ALLOWED = {
    "node/exitnode/manifest.py",
    "node/exitnode/cli.py",
    "node/exitnode/service.py",
    "node/exitnode/proxy/context.py",
    "node/exitnode/proxy/server_config.py",
    "node/exitnode/updater/upgrade.py",
    "node/exitnode/console/install.py",
    "node/exitnode/templates/exitnode-console.service",
    "node/exitnode/templates/exitnode-console-status.service",
    "node/exitnode/templates/exitnode-console-status.timer",
    "node/examples/config.example.toml",
    "node/tests/test_console_install.py",
    "node/tests/test_console_static_served.py",
    "node/tests/test_systemd_render.py",
    "node/tests/test_proxy_server_render.py",
    "node/tests/test_cli.py",
    "node/tests/test_updater.py",
    "node/tests/test_config.py",
    "node/tests/test_manifest.py",
}
TESTS = {
    "node/tests/test_console_install.py": [
        "test_extra_allow_only_for_remote_authserver",
        "test_sync_dropin_writes_only_on_change",
        "test_prepare_generates_password_once_and_empty_admin_key",
        "test_urls_lan_and_tunnel",
    ],
    "node/tests/test_console_static_served.py": ["test_package_static_files_are_served"],
    "node/tests/test_proxy_server_render.py": ["test_console_rule_only_for_local_devices_when_enabled"],
    "node/tests/test_cli.py": [
        "test_init_installs_console_when_enabled",
        "test_init_regenerates_missing_console_password",
        "test_init_updates_console_allow_when_authserver_moves",
        "test_init_skips_console_when_disabled",
        "test_console_admin_key_hides_input_on_tty",
    ],
    "node/tests/test_updater.py": ["test_restart_try_restarts_console_without_failing_upgrade"],
}
HARDENING = """Restart=on-failure
RestartSec=30
DynamicUser=true
CapabilityBoundingSet=
NoNewPrivileges=true
UMask=0077
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
IPAddressDeny=any
IPAddressAllow=localhost 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16
TasksMax=64
LimitNOFILE=1024
MemoryMax=256M
"""
EXPECTED = {
    "exitnode-console.service": """[Unit]
Description=出口节点管理网页
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Environment=PYTHONPATH=$program_path
Type=simple
ExecStart=/usr/bin/python3 -P -m exitnode --config "$config_path" console serve
LoadCredential=console-password:/var/lib/exitnode/secrets/console-password
LoadCredential=authserver-admin-key:/var/lib/exitnode/secrets/authserver-admin-key
""" + HARDENING + """
[Install]
WantedBy=multi-user.target
""",
    "exitnode-console-status.service": """[Unit]
Description=出口节点管理网页检查记录
After=network-online.target

[Service]
Environment=PYTHONPATH=$program_path
Type=oneshot
ExecStart=/usr/bin/python3 -P -m exitnode --config "$config_path" console snapshot
TimeoutStartSec=50
Restart=no
NoNewPrivileges=true
UMask=0077
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
""",
    "exitnode-console-status.timer": """[Unit]
Description=出口节点每分钟写管理网页检查记录

[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=5s
Persistent=false
Unit=exitnode-console-status.service

[Install]
WantedBy=timers.target
""",
}
EXAMPLE_TAIL = """
# 节点管理网页:局域网用 http://<本机局域网地址>:8444/ 打开;隧道里只有本机自用设备能用 http://198.18.255.2/ 打开
[console]
enabled = true
port = 8444
lan = true
"""


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def shape():
    bad = []
    for name, body in EXPECTED.items():
        path = TEMPLATES / name
        if not path.exists() or text(path) != body:
            bad.append(f"模板与契约原文不一致:{name}")
    sys.path[:0] = [str(NODE)]
    from exitnode import manifest
    from exitnode.console import install
    from exitnode.proxy.context import ProxyContext

    missing = set(EXPECTED) - manifest.UNITS
    bad += [f"安装清单缺单元 {u}" for u in sorted(missing)]
    if install.DROPIN != "/etc/systemd/system/exitnode-console.service.d/authserver.conf":
        bad.append("console/install.py 的 DROPIN 路径不是契约给的值")
    if ProxyContext.__dataclass_fields__["console_port"].default != 0:
        bad.append("ProxyContext.console_port 默认值应为 0")
    if not text(NODE / "examples/config.example.toml").endswith(EXAMPLE_TAIL):
        bad.append("示例配置末尾不是契约给的管理网页段")
    from exitnode.cli import JOURNAL_UNITS

    missing_journal = {"exitnode-console.service", "exitnode-console-status.service"} - set(JOURNAL_UNITS)
    bad += [f"诊断包的系统日志没收 {u}" for u in sorted(missing_journal)]
    if "try-restart" not in text(NODE / "exitnode/updater/upgrade.py"):
        bad.append("升级重启没有带上管理网页")
    base = subprocess.check_output(["git", "merge-base", "origin/main", "HEAD"], cwd=ROOT).decode().strip()
    golden = subprocess.run(["git", "diff", "--quiet", base, "--", "node/tests/golden"], cwd=ROOT)
    if golden.returncode:
        bad.append("黄金样本被改了")
    return bad


def tests():
    bad = []
    for file, names in TESTS.items():
        body = text(ROOT / file) if (ROOT / file).exists() else ""
        bad += [f"缺用例 {file}:{n}" for n in names if f"def {n}(" not in body]
    return bad


def scope():
    def git(*args):
        out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
        return [line.strip() for line in out.decode("utf-8").splitlines() if line.strip()]

    base = git("merge-base", "origin/main", "HEAD")[0]
    changed = set(git("diff", "--name-only", base)) | set(git("ls-files", "--others", "--exclude-standard"))
    return [f"改了圈外文件 {p}" for p in sorted(changed - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
