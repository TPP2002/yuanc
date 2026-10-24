"""只编译人工复核工具，不启动内核、浏览器或握手采集。"""

import py_compile
from pathlib import Path

import pytest


@pytest.mark.parametrize("name", ["check_configs.py", "capture_clienthello.py"])
def test_kernel_tool_compiles_without_repository_outputs(name, tmp_path):
    source = Path(__file__).resolve().parents[2] / "scripts" / "kernel" / name
    target = tmp_path / (name + "c")
    assert py_compile.compile(str(source), cfile=str(target), doraise=True) == str(target)
    assert target.is_file()
