"""出口节点基础程序。"""

__version__ = "0.1.0"


def watchdog(runner, config):
    """TODO WATCHDOG：有界恢复循环，后续卡实现。"""
    raise NotImplementedError("守护恢复未实现，见卡 WATCHDOG")


def upgrade(runner, config, version=None):
    """TODO UPDATER：来源校验、A/B 切换及健康回退，后续卡实现。"""
    raise NotImplementedError("未实现，见卡 UPDATER")
