"""PEP 440 版本解析与排序，避免为节点额外引入运行依赖。"""

import re
from functools import total_ordering

PATTERN = re.compile(r"""
    v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:(?:-(?P<post_n1>[0-9]+))|
       (?:[-_.]?(?P<post>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?:[-_.]?(?P<dev>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
""", re.IGNORECASE | re.VERBOSE)


@total_ordering
class Version:
    def __init__(self, value):
        if not isinstance(value, str) or not (match := PATTERN.fullmatch(value.strip())):
            raise ValueError("版本号格式不正确")
        group = match.groupdict()
        release = tuple(int(n) for n in group["release"].split("."))
        normalized_release = release
        while len(normalized_release) > 1 and normalized_release[-1] == 0:
            normalized_release = normalized_release[:-1]
        epoch = int(group["epoch"] or 0)
        pre = (group["pre"] or "").lower()
        pre = {"alpha": "a", "beta": "b", "c": "rc",
               "pre": "rc", "preview": "rc"}.get(pre, pre)
        pre_n = int(group["pre_n"] or 0)
        has_post = group["post"] is not None or group["post_n1"] is not None
        post_n = int(group["post_n1"] or group["post_n2"] or 0)
        has_dev = group["dev"] is not None
        dev_n = int(group["dev_n"] or 0)
        pre_key = ({"a": 0, "b": 1, "rc": 2}[pre], pre_n) if pre else (
            (-1, 0) if has_dev and not has_post else (3, 0))
        local = re.split(r"[-_.]", group["local"].lower()) if group["local"] else []
        local_key = tuple((1, int(s)) if s.isdigit() else (0, s) for s in local)
        self.key = (epoch, normalized_release, pre_key, post_n if has_post else -1,
                    dev_n if has_dev else float("inf"), local_key)
        self.text = ((str(epoch) + "!" if epoch else "") + ".".join(map(str, release))
                     + (pre + str(pre_n) if pre else "")
                     + (".post" + str(post_n) if has_post else "")
                     + (".dev" + str(dev_n) if has_dev else "")
                     + ("+" + ".".join(str(int(s)) if s.isdigit() else s for s in local)
                        if local else ""))

    def __str__(self):
        return self.text

    def __eq__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self.key == other.key

    def __lt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self.key < other.key
