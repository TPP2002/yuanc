"""按需导入更新逻辑；更新器故障不阻断其他命令。"""


def repair(config, runner):
    from .layout import repair as repair_layout

    return repair_layout(config, runner)
