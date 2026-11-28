"""工单 yc-startup-keep-no-source-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTROLLER = ROOT / "winclient/WinClient.Core/Client/ClientController.cs"
TEST_PATH = "winclient/WinClient.Tests/ControllerTests.cs"
GUARD_DOC = ROOT / "docs/winclient/断网保护加固说明.md"
SERVICE_DOC = ROOT / "docs/winclient/服务化与自启说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Client/ClientController.cs",
    TEST_PATH,
    "docs/winclient/断网保护加固说明.md",
    "docs/winclient/服务化与自启说明.md",
}
PAIRING_TEXT = (
    "上次的连接没有断开，但现在找不到配对文件。断网保护保持，电脑暂时上不了网。"
    "请点「断开」恢复原来的网络，重新导入配对文件后再连接。"
)
CREDENTIAL_TEXT = (
    "上次的连接没有断开，但现在找不到登录凭据。断网保护保持，电脑暂时上不了网。"
    "请点「断开」恢复原来的网络，重新兑换邀请码后再连接。"
)
JOURNAL_LINE = "启动：找不到配对文件或登录凭据，断网保护保持，停在需人工处理"
RENAMED = {
    "StartupPendingProtectionWithoutServerRecovers": "StartupKeptWithoutServerParksWithProtection",
    "StartupPendingProtectionWithoutCredentialsRecovers": "StartupKeptWithoutCredentialsParksWithProtection",
}
NEW_TESTS = [
    "StartupKeptCredentialReadFailureParksWithProtection",
    "StartupKeptParkedDisconnectRestoresNetwork",
    "StartupKeptParkedConnectKeepsGuidance",
    "StartupKeptParkedWritesJournalLine",
    "StartupKeptWithoutRecordStillRecovers",
    "StartupKeptFlagOffStillRecovers",
]
KEPT_TESTS = [
    "StartupKeepsPairingProtectionAndConnectsRegardlessOfAutoConnect",
    "HeldProtectionKeepsTunnelWhenRoutesFail",
    "StartupWithoutPendingStateStillRecoversThenAutomaticallyConnects",
    "StartupAuthNetworkRetriesExhaustWithoutEverRemovingProtection",
]


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def between(source, start, end):
    """取 start 到 end 之间的正文;找不到返回空串。"""
    parts = source.split(start, 1)
    return parts[1].split(end, 1)[0] if len(parts) == 2 else ""


def shape():
    bad = []
    source = text(CONTROLLER)
    for name, value in (("KeptWithoutPairingMessage", PAIRING_TEXT),
                        ("KeptWithoutCredentialsMessage", CREDENTIAL_TEXT)):
        if f'internal const string {name} = "{value}";' not in source:
            bad.append(f"ClientController.cs 缺常量 {name},或文字与契约不一致")
    init = between(source, "public async Task InitializeAsync(", "public async Task RedeemAsync(")
    if not init:
        bad.append("找不到 InitializeAsync")
    else:
        for token in ("KeptWithoutPairingMessage", "KeptWithoutCredentialsMessage"):
            if token not in init:
                bad.append(f"InitializeAsync 没有用到 {token}")
        if JOURNAL_LINE not in init:
            bad.append("InitializeAsync 没有写「启动：找不到配对文件或登录凭据…」这行记录")
        if "ConnectionEventKind.OperationFailed" not in init:
            bad.append("InitializeAsync 没有用 OperationFailed 让状态停在需人工处理")
        for token, label in (("protectionVerified = true;", "可用来源那一路的 protectionVerified = true"),
                             ("firewall.RecoverAsync()", "恢复分支的 firewall.RecoverAsync()"),
                             ("启动：接回断网保护，随后自动连接", "可用来源那一路的记录"),
                             ("启动：已做启动恢复", "恢复分支的记录")):
            if token not in init:
                bad.append(f"InitializeAsync 里{label}不见了")
    connect = between(source, "internal async Task ConnectAsync(bool fromUser)", "public async Task DisconnectAsync()")
    if "KeptWithoutPairingMessage" not in connect:
        bad.append("ConnectAsync 在没有会话来源且保护保持时没有保留提示")
    change = between(source, "public async Task ChangeSessionSourceAsync(", "private async Task FailAsync(")
    if "请先点击断开，再更换配对文件。" not in change or "if (protection ||" not in change:
        bad.append("ChangeSessionSourceAsync 被改了(保护在时仍应拒绝更换配对文件)")
    return bad


def tests():
    bad = []
    body = text(ROOT / TEST_PATH)
    old = git("show", f"{base()}:{TEST_PATH}").replace("\r\n", "\n")
    for before, after in RENAMED.items():
        if f" {before}(" in body:
            bad.append(f"既有用例 {before} 还没改名")
        if f"public async Task {after}(" not in body:
            bad.append(f"缺改名后的用例 {after}")
    for name in NEW_TESTS:
        if f"public async Task {name}(" not in body:
            bad.append(f"缺新用例 {name}")
    for name in KEPT_TESTS:
        if between(body, f" {name}(", "\n    }\n") != between(old, f" {name}(", "\n    }\n"):
            bad.append(f"既有用例 {name} 被改了")

    def count(source):
        return len(re.findall(r"^\s*\[(?:Fact|Theory)", source, flags=re.M))

    if count(body) < count(old) + len(NEW_TESTS):
        bad.append(f"用例数不对:原有 {count(old)} 个,现在 {count(body)} 个,至少应为 {count(old) + len(NEW_TESTS)} 个")
    if body.count("Skip =") > old.count("Skip ="):
        bad.append("测试文件里新增了跳过")
    old_names = set(re.findall(r"public (?:async )?(?:Task|void) (\w+)\(", old))
    new_names = set(re.findall(r"public (?:async )?(?:Task|void) (\w+)\(", body))
    lost = sorted(old_names - new_names - set(RENAMED))
    bad += [f"既有用例 {name} 不见了" for name in lost]
    return bad


def docs():
    bad = []
    guard = text(GUARD_DOC)
    section = between(guard, "\n## 服务重启时保持保护\n", "\n## ")
    if "### 上次连着、启动时找不到配对文件或登录凭据" not in section:
        bad.append("断网保护加固说明「服务重启时保持保护」一节缺新小节")
    for value, label in ((PAIRING_TEXT, "自用版提示原文"), (CREDENTIAL_TEXT, "分发版提示原文"),
                         (JOURNAL_LINE, "记录原文"), ("secure/pairing.bin", "真机待验证那一条")):
        if value not in section:
            bad.append(f"断网保护加固说明「服务重启时保持保护」一节缺{label}")
    if "或没有配对／鉴权凭据、没有服务器配置时，才走原有恢复网络路径" in guard:
        bad.append("断网保护加固说明里旧说法还在(没有配对／鉴权凭据…才走原有恢复网络路径)")
    if "只有期望明确为断开，或没有恢复记录时，才走原有恢复网络路径；" not in section:
        bad.append("断网保护加固说明里那句没按契约改")
    service = text(SERVICE_DOC)
    if "没有配对／凭据或服务器配置时走既有恢复路径" in service:
        bad.append("服务化与自启说明里旧说法还在(没有配对／凭据或服务器配置时走既有恢复路径)")
    if "保护保持并停在「需人工处理」，用户点「断开」才恢复网络" not in service:
        bad.append("服务化与自启说明里那句没按契约改")
    return bad


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "docs": docs, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
