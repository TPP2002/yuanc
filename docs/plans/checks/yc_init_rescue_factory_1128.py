"""工单 yc-init-rescue-factory-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CLI_PATH = "node/exitnode/cli.py"
TEST_PATH = "node/tests/test_cli.py"
ALLOWED = {CLI_PATH, TEST_PATH}

OLD_MESSAGE = "已有救援包内容不同"
CODE_MESSAGE = "独立救援代码与当前程序自带的不一致，请先运行 exitnode rescue refresh，再重跑安装"
REBUILT_MESSAGE = "出厂包不完整，已按当前程序重建"
BLOCK_START = "            runner.mkdir(rescue_probes.RESCUE, 0o755)\n"
BLOCK_END = "            for unit in sorted(rescue_units):\n"

NEW_HELPERS = ["simulate_upgrade", "rescue_tree"]
NEW_TESTS = {
    "test_reinit_after_upgrade_and_removal_keeps_older_factory": [
        'simulate_upgrade(runner, "0.2.0")', "main([command], runner) == 0", 'rescue_tree(runner, "factory") == factory',
        '"安装救援单元：已完成；" in out', '["version"] == "0.1.0"',
        'runner.readlink("/opt/exitnode/current") == "/opt/exitnode/releases/0.2.0"'],
    "test_init_rebuilds_incomplete_factory": [
        '"半截"', f'"{REBUILT_MESSAGE}" in', 'layout.valid_release(runner, "/opt/exitnode-rescue/factory")',
        'layout.hashes(runner, "/opt/exitnode-rescue/factory") == layout.hashes(runner, current)',
        '"出厂包不完整" not in'],
    "test_init_points_to_refresh_when_rescue_code_differs": [
        'main(["init"], runner) == 1', f'"{CODE_MESSAGE}" in out', f'"{OLD_MESSAGE}" not in out',
        'runner.files[path] == "# older rescue code\\n"', 'rescue_tree(runner, "factory") == factory'],
    "test_reinit_after_upgrade_skips_finished_rescue_step": [
        'simulate_upgrade(runner, "0.2.0")', '"安装救援单元：已完成，跳过" in', 'rescue_tree(runner, "factory") == factory'],
}
PARAMETRIZE = ('@pytest.mark.parametrize("command", ["rollback", "uninstall"])\n'
               "def test_reinit_after_upgrade_and_removal_keeps_older_factory(command, capsys):")
SKIPS = r"pytest\.mark\.(?:skip|skipif|xfail)\b|pytest\.(?:skip|xfail|importorskip)\s*\("


def text(path):
    return Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    return git("show", f"{base()}:{path}").replace("\r\n", "\n")


def function(source, name):
    """取模块级一个函数的正文:从 def 那行到下一个顶格语句之前。"""
    parts = source.split(f"\ndef {name}(", 1)
    return re.split(r"\n(?=\S)", parts[1], maxsplit=1)[0].rstrip() if len(parts) == 2 else ""


def around(source):
    """把 cli.py 切成三段:要改的那一段之前、那一段本身、之后。切不出来返回 None。"""
    if source.count(BLOCK_START) != 1:
        return None
    head, rest = source.split(BLOCK_START, 1)
    if BLOCK_END not in rest:
        return None
    block, tail = rest.split(BLOCK_END, 1)
    return head, block, tail


def shape_problems(new, old):
    bad = []
    was, now = around(old), around(new)
    if was is None:
        return ["检查脚本在改动前的 cli.py 里找不到要改的那一段,请交 blocked 告诉派单方"]
    if now is None:
        return ["cli.py 里找不到「runner.mkdir(rescue_probes.RESCUE, 0o755)」到「for unit in sorted(rescue_units):」这一段(这两行不许动)"]
    if now[0] != was[0] or now[2] != was[2]:
        bad.append("cli.py 在要改的那一段之外有改动(只许改 install_rescue 里建目录之后、写救援服务文件之前的那一段)")
    block = now[1]
    if OLD_MESSAGE in new:
        bad.append(f"cli.py 里还留着旧提示「{OLD_MESSAGE}…」")
    for message in (CODE_MESSAGE, REBUILT_MESSAGE):
        if message not in block:
            bad.append(f"那一段里没有「{message}」(文字要一字不差)")
    for token, why in (("layout.valid_release(runner, ", "出厂包存在时要先校验清单与文件哈希"),
                       ("runner.remove_tree(", "校验不过的出厂包要先删掉再复制"),
                       ("successful.append(", "重建出厂包要写进成功项")):
        if token not in block:
            bad.append(f"那一段里没有 {token}:{why}")
    if block.count("runner.copy_tree(") < 3:
        bad.append("那一段里的复制少了:独立救援代码首次复制、出厂包首次复制、出厂包重建,各一处")
    if "refresh(" in block or "rescue_state" in block:
        bad.append("安装不许替维护人员刷新独立救援代码")
    return bad


def tests_problems(new, old):
    bad = []
    old_names = re.findall(r"^def (\w+)\(", old, flags=re.M)
    if len(old_names) < 60:
        bad.append("检查脚本没认全改动前 test_cli.py 里的函数,请交 blocked 告诉派单方")
    for name in old_names:
        was, now = function(old, name), function(new, name)
        if not now:
            bad.append(f"既有的 {name} 不见了")
        elif was != now:
            bad.append(f"既有的 {name} 被改了")
    if not new.startswith(old.rstrip("\n")):
        bad.append("test_cli.py 原有内容被改动:新内容只许加在文件末尾")
    for name in NEW_HELPERS:
        if name in old_names or not function(new, name):
            bad.append(f"缺辅助函数 {name}")
    for name, tokens in NEW_TESTS.items():
        body = function(new, name)
        if name in old_names or not body:
            bad.append(f"缺新用例 {name}")
            continue
        for token in tokens:
            if token not in body:
                bad.append(f"新用例 {name} 里没有契约要求的 {token}")
    if PARAMETRIZE not in new:
        bad.append("test_reinit_after_upgrade_and_removal_keeps_older_factory 要按 rollback、uninstall 两个参数跑")
    if len(re.findall(SKIPS, new)) > len(re.findall(SKIPS, old)):
        bad.append("test_cli.py 里新增了跳过或预期失败")
    return bad


def shape():
    return shape_problems(text(ROOT / CLI_PATH), before(CLI_PATH))


def tests():
    return tests_problems(text(ROOT / TEST_PATH), before(TEST_PATH))


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
