# 澳洲出口客户端 · 界面设计规范(DESIGN.md)

> 版本 v1(2026-10-22)。卡 WINCLIENT-UI-DASHBOARD-STYLE-1022。
> **正本关系**:`样张-主窗口.html` 里的 CSS 是 token 与组件样式的正本,施工方把它搬进 WPF 资源字典,**不是看图重画**;本文件讲规则、状态表、WPF 键名映射和底线核对。两者冲突以样张 CSS 的数值为准、以本文的规则为准。
> 来源:看板 `F:/project-dashboard/web/src/styles/base.css` 的色板、尺度与状态瓦片语言;三处按本项目底线压深(最淡灰字、琥珀字、控件边框)。

## 1. 适用范围

Windows 客户端界面程序(`winclient/WinClient.App`)的全部窗口、页面、控件、托盘图标与动效。后台服务、协议、`WinClient.Core` 不在范围内。

## 2. Token

### 2.1 颜色(按角色命名;组件里只许引用变量)

```yaml
light:
  bg: "#fbfbfa"          # 窗口底
  surface: "#ffffff"     # 卡片
  surface-2: "#f6f6f5"   # 行、次级按钮底
  surface-3: "#eeeeed"   # 选中导航项、按下
  line: "#e4e4e2"        # 卡片与行的细线(不是控件边界,可低于 3:1)
  line-strong: "#d2d2cf" # 窗口外框
  ctrl-border: "#8a8a85" # 控件边界(按钮、输入框、开关、单选圈)≥3:1
  text: "#1a1a19"
  text-2: "#5c5c58"
  text-3: "#6b6b66"      # 看板原值 #8e8e89 压深到 5.17:1
  ok: "#2c7a45"      ; ok-bg: "#e8f4ec"
  warn: "#7d5609"    ; warn-bg: "#fdf3e0"   # 看板原值 #9a6b12 压深到 5.95:1
  bad: "#b3382f"     ; bad-bg: "#fdecea"
  info: "#2b5fa8"    ; info-bg: "#e8f0fb"
  n: "#6b6b66"       ; n-bg: "#eeeeed"
  action: "#1a1a19"  ; action-text: "#fbfbfa" ; action-hover: "#2e2e2c" ; action-press: "#000000"
  focus: "#2b5fa8"
  shadow: "0 1px 2px rgba(0,0,0,.05), 0 1px 3px rgba(0,0,0,.04)"
dark:
  bg: "#0d0d0e" ; surface: "#151516" ; surface-2: "#1b1b1d" ; surface-3: "#232326"
  line: "#242426" ; line-strong: "#343437" ; ctrl-border: "#6a6a6f"
  text: "#e7e7e8" ; text-2: "#9a9a9e" ; text-3: "#8d8d92"   # 看板原值 #6a6a6f 压亮到 5.88:1
  ok: "#6fbf82"   ; ok-bg: "#17251b"
  warn: "#d9a441" ; warn-bg: "#241d10"
  bad: "#e0736a"  ; bad-bg: "#2a1715"
  info: "#6d9eea" ; info-bg: "#141d2b"
  n: "#8e8e8e"    ; n-bg: "#232326"
  action: "#e7e7e8" ; action-text: "#0d0d0e" ; action-hover: "#d3d3d5" ; action-press: "#ffffff"
  focus: "#6d9eea"
  shadow: none
```

灯条色站(每条首尾同色,循环无接缝;`spec-ok`/`spec-bad`/`spec-n` 深色另有一组,见样张 CSS):

```yaml
spec-info: [ "#4a9eff", "#4ad9c4", "#6d8cff", "#4a9eff" ]   # 连接中 / 重连中
spec-warn: [ "#f0b429", "#f5825b", "#f6d365", "#f0b429" ]   # 需要重新登录
spec-ok:   [ "#6fbf82", "#2c7a45", "#a8e6b9", "#6fbf82" ]   # 预留,现版本不流
spec-bad:  [ "#e0736a", "#8a2f27", "#f2a59d", "#e0736a" ]   # 预留,出错不流
spec-n:    [ "#c9c9c6", "#8e8e89", "#e4e4e2", "#c9c9c6" ]   # 预留
```

### 2.2 字

```yaml
font-cn:   "Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", system-ui   # WPF: "Microsoft YaHei UI, Microsoft YaHei, Segoe UI"
font-mono: "Cascadia Mono", Consolas, ui-monospace                             # 只给 IP / 版本 / 路径 / 邀请码
size:  { xs: 12, sm: 14, base: 16, md: 18, lg: 20, xl: 24, 2xl: 28 }           # px;HTML 里是 rem
weight: { regular: 400, bold: 700 }                                            # 只有两档;SemiBold 不用
line-height: { ui: 1.5, title: 1.25, body: 1.7 }
```

用法:正文 16;辅助、行标签、副标题 14;12 只给徽章与右侧时间标注;页标题 24;英雄状态名 24;窗口标题栏 14。

### 2.3 尺度

```yaml
space:  { 1: 4, 2: 8, 3: 12, 4: 16, 5: 24, 6: 32, 7: 48 }
radius: { sm: 4, md: 6, lg: 8, tile: 7, hero: 14 }
window: { width: 880, height: 600, min-width: 760, min-height: 540 }
sidebar: 200
row-height: 44          # 四行状态最小高
button-height: 40       # 小号 32
hit-area: ">= 32x32, 相邻可点目标间隔 >= 8"
```

### 2.4 动效

```yaml
dur: { press: 120ms, small: 180ms, panel: 240ms, draw: 600ms, number: 300ms, flow: 3.4s, flow-fast: 2.4s }
ease: { out: "cubic-bezier(0,0,0,1)", move: "cubic-bezier(.2,0,0,1)", exit: "cubic-bezier(.3,0,1,1)" }
gate: "SystemParameters.ClientAreaAnimation == false → 一切动画不跑,瓦片边框退化为实色"
```

## 3. 组件规则

| 组件 | 规则 |
|---|---|
| 按钮(次级) | 高 40,左右内距 16,边框 ctrl-border,底 surface-2;悬停 surface-3;按下 surface-3 + 缩放 .97(仅动画开启时);聚焦 2px focus 描边外扩 2px;禁用 55% 不透明 + 旁边一句原因;忙碌:文字换成「正在…」且不可再点 |
| 按钮(主) | 底 action、字 action-text、粗体;悬停 action-hover;按下 action-press;**一屏只有一个**;英雄卡右侧固定列宽 144,文字不换行 |
| 按钮(安静) | 透明底、无边框、字 text-2;用于「移除」「清除本机配对文件」(后者字色 bad) |
| 输入框 | 高 40,边框 ctrl-border,聚焦 2px focus 内描边;邀请码框用等宽字 + 字距 .04em |
| 选择卡 | 整块可点的单选:20px 圆圈 + 粗标题 + 一句说明;选中时边框 info + 1px 外描边 + info-bg 底;禁用整块 60% 并在下方写原因 |
| 开关 | 40×22 轨道,滑块 16,180ms 滑动;开启轨道 info-bg + info 边 |
| 行(状态行) | surface-2 底 + line 细线 + 圆角 6,最小高 44;左 20px 瓦片,标签 88px text-2 14,正文 16,右侧时间标注 text-3 等宽 14 |
| 徽章 | 12px 字,2px/8px 内距,语义色底 + 语义色字;只用于模式、自检汇总 |
| 卡片 | surface 底、line 细线、圆角 8、阴影 shadow(深色无);不套卡 |
| 侧栏导航项 | 高 36,图标 20 + 文字 16;选中 surface-3 底 + line 边 + 粗体;悬停 surface-2 |
| 侧栏底部 | 服务状态:圆点(ok/warn/bad/n)+「后台服务 · 运行中 / 未运行 / 未安装 / 已中断」,第二行等宽 12「版本 x.y.z」(没有版本时隐藏) |
| 主消息槽 | 英雄卡下方,固定两行高(14px × 1.5 × 2),空着也占位;红 = bad,绿 = ok,默认 text-2 |
| 提示行 | 页面底部 text-3 14;需要警示的用 warn |

**状态瓦片(StatusTile)**——记忆点,语法与看板一致:

| 属性 | 取值 |
|---|---|
| Size | 20(行)/ 56(英雄) |
| Tone | n / info / warn / ok / bad(决定底色 tone-bg、记号色 tone、灯条 tone-spec) |
| Glyph | ring 虚线环 / dots 三点 / bars 三柱 / check 勾 / spin 回旋箭头 / ask 问号 / bang 感叹 / x 叉 / plug 插头(24 视框 path 见样张 `GLYPH`) |
| Flow | none 静止(边框 line)/ forward 正向流 / reverse 反向流 / fast 快流(2.4s);动画关闭时流动态退化为实色 tone 边框 |
| Filled | 整块填 tone 色、记号用 bg 色(只给「已连接」) |
| Dim | 50% 不透明(「跳过」) |

结构:外圈(边框层,3px / 1.5px)→ 内层(tone-bg)→ SVG 记号(stroke 2 / 2.2,圆头)。

## 4. 状态表(施工方按此映射,写成纯函数并有测试)

### 4.1 连接页英雄卡 + 主按钮 + 托盘图标

输入:ViewModel 的 `availability`(NeedInstall / NeedRepair / Unavailable / Ready)+ `ControlSnapshot`。

| 条件 | 瓦片 | 状态名 | 副标题 | 主按钮 | 托盘 |
|---|---|---|---|---|---|
| NeedInstall | n · plug · 静止 | 需安装后台服务 | 首次使用请安装后台服务,确认一次管理员权限后即可使用 | 安装后台服务 | tray-n |
| NeedRepair | warn · bang · 静止 | 后台服务未运行 | 点「修复后台服务」把它启动起来(需管理员确认一次) | 修复后台服务 | tray-warn |
| Unavailable(连不上 / 中断 / 身份核验失败) | bad · x · 静止 | snapshot.Status 原文 | snapshot.Message 原文(红) | 重新连接后台服务 | tray-bad |
| Ready · Disconnected | n · ring · 静止 | 未连接 | 全部流量:「点「连接」后,所有程序都从澳洲出口上网」;仅指定程序:「点「连接」后,指定的 N 个程序从澳洲出口上网」 | 连接 | tray-n |
| Ready · Connecting | info · bars · forward | 正在连接 | snapshot.Message 原文 | 断开 | tray-info |
| Ready · Connected,GuardStatus 为空或「正常」 | ok · check · 填满,勾画一次 | 已连接 | 按 ExitStatus:已核验 →「出口 <IP> · 与澳洲节点一致」;核验中 →「正在核验出口…」;无法核验 →「出口无法核验(隧道内暂无回应)」(warn);不一致 →「出口 <IP> 与澳洲节点不一致,请联系管理员」(bad) | 断开 | tray-ok |
| Ready · Connected,GuardStatus 是告警(非空且非「正常」) | ok · check · 填满 | 已连接 | GuardStatus 原文(红;含「断网保护未能重新套用…」「…断网保护可能失效…」「巡检失败,下一轮重试」后者用 warn) | 断开 | tray-warn |
| Ready · Reconnecting | info · spin · reverse | 正在重连 | snapshot.Message 原文 | 断开 | tray-info |
| Ready · NeedsLogin | warn · ask · fast | 需要重新登录 | snapshot.Message 原文(warn);下方次级按钮「去兑换邀请码」切到账号页 | 按 ShouldDisconnect:断开 / 连接 | tray-warn |
| Ready · NeedsManual | bad · bang · 静止 | 需要处理 | snapshot.Message 原文(红) | 按 ShouldDisconnect:断开 / 连接 | tray-bad |
| IsBusy(任一状态) | 瓦片不变 | 不变 | 不变 | 文字「正在…」(连接→正在连接、断开→正在断开、其余→正在处理),不可点 | 不变 |

主消息槽永远显示 `Message`(ViewModel 现有拼接,含「后台已更新到…」),与副标题重复时照样显示(副标题是摘要,消息槽是原文)。

### 4.2 四行状态

| 行 | 输入 | 瓦片 → 文字 |
|---|---|---|
| 出口 IP | ExitStatus / ExitIp | 未检测 → n·ring「待检测」;核验中 → info·dots「核验中…」;已核验 → ok·check「<IP> · 与澳洲节点一致」+ 右「5 分钟后复查」;已核验(后台服务出口)→ ok·check「<IP> · 与澳洲节点一致(仅证明后台服务出口)」;不一致 / 不一致(后台服务出口)→ bad·bang「<IP> · 与澳洲节点不一致,请联系管理员」;无法核验 → warn·ask「无法核验(隧道内暂无回应)」 |
| 断网保护 | ProtectionActive / GuardStatus | 未启用 → n·ring「未启用,连接时自动开启」;启用且 GuardStatus 空 → ok·check「已开启,60 秒后首次巡检」;「正常」→ ok·check「正常,每 60 秒巡检一次」;「巡检失败,下一轮重试」→ warn·ask 原文;其余告警 → bad·bang 原文;NeedsLogin 且启用 → ok·check「保持中(到期后不撤)」 |
| 环境自检 | SelfCheckStatus | 未检测 → n·ring;检测中 → info·dots;含「未通过」→ bad·x 原文;含「未能检查」→ warn·ask 原文;其余 → ok·check 原文;右侧「看明细在「环境一致」」 |
| 环境一致性 | EnvironmentEnabled / EnvironmentStatus | 未应用 → n·ring「未应用」;未启用 → n·ring·dim「未启用」;已切换到澳洲时区与浏览器策略 → ok·check「已应用:澳洲东部时区、Chrome 与 Edge 首选语言」;含「失败」→ bad·bang 原文 |

### 4.3 其余四页

- **代理范围**:两张选择卡(全部流量(推荐)/ 仅指定程序)绑定 RoutingIsGlobal / RoutingIsApps;指定程序清单每行 info·check 瓦片 + 等宽路径 + 安静按钮「移除」;「添加程序…」;`CanChangeRouting` 为假时整块 60% 并在底部 warn 提示「连接中不能改代理范围,请先在「连接」页断开。」;清单为空时显示虚线空态「还没有指定程序;点「添加程序…」选一个 .exe」。
- **环境一致**:开关卡(EnvironmentEnabled,CanUseConnection 为假时禁用并写原因)+ 自检明细(打开本页与 SelfCheckStatus 变化时经 `read_selfcheck` 读 JSON;每项一行,序号做标签,result 映射:通过 ok·check / 未通过 bad·x / 跳过 n·ring·dim / 无法核验 warn·ask,右侧写 result;detail 放在名称后用 text-2);读不到时空态「连上一次后才有自检明细」。
- **账号与配对**:两张卡(自用:导入配对文件;分发版:邀请码输入 + 「兑换邀请码」);右下安静红字「清除本机配对文件」;禁用时写原因;Mode 徽章在页头。
- **更新与诊断**:版本卡(后台服务 ServiceVersion、界面程序 ControlSnapshot.CurrentVersion、上次检查 Update.CheckedAt、UpdateMessage)+「检查更新」;诊断段 + 「导出诊断…」;更新进行中(Update.Stage 非 idle 且非终态)显示 info·dots 行,超过 1 秒才出现。

## 5. 动效清单(四用途之外一个不加)

| 动效 | 用途 | 触发 | 时长 / 缓动 | 动画关闭时 |
|---|---|---|---|---|
| 按钮按下 | 反馈 | 按下 | 120ms,底色变深 + 缩 .97 | 只换底色,不缩 |
| 导航项悬停 / 选中 | 反馈 | 悬停、点击 | 120ms 底色 | 瞬时换色 |
| 开关滑块 | 反馈 | 切换 | 180ms move | 瞬时跳 |
| 瓦片灯条流动 | 等待安慰 | 连接中 / 重连中 / 需要重新登录 | 3.4s 线性循环(反向 / 2.4s 变体),背景 200% 宽推 -200% | 实色边框静止 |
| 瓦片记号(三柱长 / 箭头回旋 / 问号呼吸 / 三点起伏) | 等待安慰 | 同上 | 2.4s / 3.2s / 2.4s / 1.6s 循环,只动 transform / opacity | 静止 |
| 连上勾画一笔 | 状态切换(记忆点) | 进入 Connected 那一次 | 600ms ease-out,stroke-dashoffset 26 → 0,只播一次 | 直接显示勾 |
| 瓦片底色过渡 | 状态切换 | Tone 变化 | 180ms | 瞬时换色 |
| 切页 | 空间连续 | 换导航项 | 180ms 淡入 + 上移 6px | 瞬时切换 |
| 首屏四行错开 | 状态切换 | 窗口首次显示 | 每行 140ms,延迟 0/30/60/90ms,只首次 | 不播 |
| 出口 IP 数字换了 | 状态切换 | ExitIp 变化 | 300ms 淡入上移 4px | 不播 |

不做:卡片悬停抬起;每节淡入;背景粒子;主按钮脉冲;任何无限循环但没在等的东西。

**门**:`MotionSettings.Enabled = SystemParameters.ClientAreaAnimation`,`SystemEvents.UserPreferenceChanged` 时重算;测试可覆盖。关闭时 Storyboard 一个都不启动(不是跑完再停)。

## 6. 布局

- 窗口 880×600,最小 760×540,居中启动;内容区可纵向滚动,侧栏与英雄卡不滚。
- 侧栏 200:导航五项(连接 / 代理范围 / 环境一致 / 账号与配对 / 更新与诊断,图标 plug / layers / sun / key / download,线宽 1.75)+ 底部服务状态。
- 页面内距 24/32;页头 = 标题 24 粗 + 徽章;连接页:英雄卡(56 瓦片 + 状态名 + 副标题 + 右侧主按钮列 144)→ 主消息槽(固定两行)→ 四行状态 → 托盘提示。
- 主按钮在连接 / 连接中 / 已连接 / 重连 / 出错全过程中位置不变(测试断言)。
- 深色时标题栏跟随(`DwmSetWindowAttribute` 20,失败忽略)。

## 7. WPF 资源键映射(施工方照此命名;所有 XAML 用 `DynamicResource`)

| CSS 变量 | 资源键(Color) | 资源键(Brush) |
|---|---|---|
| --bg | Yc.Color.Bg | Yc.Bg |
| --surface / -2 / -3 | Yc.Color.Surface / Surface2 / Surface3 | Yc.Surface / Yc.Surface2 / Yc.Surface3 |
| --line / --line-strong / --ctrl-border | Yc.Color.Line / LineStrong / CtrlBorder | Yc.Line / Yc.LineStrong / Yc.CtrlBorder |
| --text / -2 / -3 | Yc.Color.Text / Text2 / Text3 | Yc.Text / Yc.Text2 / Yc.Text3 |
| --ok / --ok-bg(warn、bad、info、n 同) | Yc.Color.Ok / OkBg … | Yc.Ok / Yc.OkBg … |
| --action / -text / -hover / -press | Yc.Color.Action… | Yc.Action / Yc.ActionText / Yc.ActionHover / Yc.ActionPress |
| --focus | Yc.Color.Focus | Yc.Focus |
| --spec-info / warn / ok / bad / n | — | Yc.Spec.Info / Warn / Ok / Bad / N(LinearGradientBrush,StartPoint 0,0 EndPoint 1,0,SpreadMethod Repeat,色站 0 / .33 / .66 / 1) |

| 其它 | 资源键 |
|---|---|
| 字体 | Yc.Font.Cn(FontFamily)/ Yc.Font.Mono |
| 字号 | Yc.FontSize.Xs / Sm / Base / Md / Lg / Xl / Xxl(Double 12/14/16/18/20/24/28) |
| 圆角 | Yc.Radius.Sm / Md / Lg / Tile / Hero(CornerRadius) |
| 间距 | Yc.Space.1 … Yc.Space.7(Double) |
| 时长 | Yc.Dur.Press / Small / Panel / Draw / Number / Flow / FlowFast(Duration) |
| 阴影 | Yc.Shadow(DropShadowEffect 或 null) |

文件:`Themes/Tokens.Light.xaml`、`Themes/Tokens.Dark.xaml`(只放颜色与阴影)、`Themes/Base.xaml`(字体、字号、圆角、间距、时长)、`Themes/Controls.xaml`(样式)、`Themes/Glyphs.xaml`(记号与图标 Geometry)。`ThemeManager.Apply(ResourceDictionary target, ThemeKind kind)` 把对应 Tokens 字典换进 target 的 MergedDictionaries;App 启动时作用于 `Application.Current.Resources`,测试里作用于被测窗口的 `Resources`。主题来源:注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme`(0 = 深色;读不到按浅色),`SystemEvents.UserPreferenceChanged` 时重读。

## 8. 底线核对(施工方交活前逐条勾)

- [ ] 文字对比:浅色 text-3 5.17、warn 5.95、n 4.61;深色 text-3 5.88;控件边框 3.18 / 3.61;焦点环 ≥3。
- [ ] 字号:正文 16,辅助 14,12 只给徽章与右侧标注;没有 11。
- [ ] 热区:按钮 ≥32 高;导航项 36;开关 40×22 但可点区域整行;相邻按钮间隔 ≥8。
- [ ] 每个可交互元素有焦点样式(FocusVisualStyle 2px focus);Tab 顺序:导航 → 页内自上而下。
- [ ] 六态:默认 / 悬停 / 聚焦 / 按下 / 禁用(带原因)/ 忙碌;数据区:空 / 加载 / 出错 / 成功。
- [ ] 主按钮位置在八种状态下不变(测试截图断言);主消息槽固定两行。
- [ ] 状态不只靠颜色:瓦片记号 + 文字同时说。
- [ ] 动效不碰布局属性;位移 / 缩放 / 流光全在动画门内;瞬时换色在任何设置下都有。
- [ ] 没有 emoji、没有 Unicode 符号当图标(「⚠」「✓」「✗」都不许)。
- [ ] 组件里没有裸色值、裸字号(`#` 开头的颜色只许出现在 Tokens 字典里)。
- [ ] 中文页;英文只在 IP / 版本 / 路径 / en-AU。
- [ ] 不放假数据:版本、IP、路径全部来自快照;样张里的演示值不进代码。
