param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string]$OutDir, [string]$ExpectVersion, [switch]$ExpectTestBuild)
# 出包后界面试跑:只开界面,核对「测试包」字样和版本号,点「导出诊断…」并确认文件写出、界面给出结果;不点安装、不点连接。
# 退出码:0 通过,1 没通过,3 这台电脑现在没法试。
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class NativeDialog {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumProc proc, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "SendMessageW")] public static extern IntPtr SendMessageGet(IntPtr hwnd, uint msg, IntPtr wParam, StringBuilder lParam);
    [DllImport("user32.dll", EntryPoint = "PostMessageW")] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    public static string ClassOf(IntPtr hwnd) { var text = new StringBuilder(96); GetClassName(hwnd, text, text.Capacity); return text.ToString(); }
    public static string GetText(IntPtr hwnd) { var text = new StringBuilder(1024); SendMessageGet(hwnd, 0x000D, (IntPtr)text.Capacity, text); return text.ToString(); }
    public static IntPtr FindChild(IntPtr parent, string className, int id) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, (hwnd, _) => {
            if (ClassOf(hwnd) == className && GetDlgCtrlID(hwnd) == id) { found = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    // 保存对话框的文件名框:Edit 的上一层是 ComboBox,再上一层是 FloatNotifySink。
    public static IntPtr FindFileNameEdit(IntPtr dialog) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(dialog, (hwnd, _) => {
            if (ClassOf(hwnd) != "Edit") return true;
            var combo = GetParent(hwnd);
            if (ClassOf(combo) == "ComboBox" && ClassOf(GetParent(combo)) == "FloatNotifySink") { found = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@
$A = [System.Windows.Automation.AutomationElement]
$T = [System.Windows.Automation.TreeScope]
$C = [System.Windows.Automation.ControlType]
function Cond($prop, $value) { New-Object System.Windows.Automation.PropertyCondition($prop, $value) }
function Both($a, $b) { New-Object System.Windows.Automation.AndCondition($a, $b) }
function Wait-For([scriptblock]$probe, [int]$seconds, [string]$what) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $found = & $probe
        if ($found) { return $found }
        Start-Sleep -Milliseconds 300
    }
    throw ('等了 ' + $seconds + ' 秒没等到' + $what)
}
function Get-Texts($element) {
    $all = $element.FindAll($T::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($item in $all) {
        $name = $item.Current.Name
        if ($name) { $item.Current.ControlType.ProgrammaticName.Replace('ControlType.', '') + ':' + $name }
    }
}
# 截图只留作事后查看,存不成(比如屏幕锁着)不算试跑失败。
function Save-Shot($element, [string]$path) {
    try {
        try { $element.SetFocus() } catch { }
        Start-Sleep -Milliseconds 800
        $r = $element.Current.BoundingRectangle
        $bmp = New-Object System.Drawing.Bitmap([int]$r.Width, [int]$r.Height)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bmp.Size)
        $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
    } catch { Write-Output ('== 截图没存成:' + $_.Exception.Message) }
}

if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
    Write-Output ('界面试跑没通过:找不到程序 ' + $Exe)
    exit 1
}
if (-not [Environment]::UserInteractive) {
    Write-Output '界面试跑没法做:当前不是看得到桌面的登录会话。'
    exit 3
}
if (Get-Service -Name 'YuanCService' -ErrorAction SilentlyContinue) {
    Write-Output '界面试跑没法做:这台电脑装了本产品的后台服务,新程序一启动就会转交给已安装的那一份。'
    exit 3
}
$running = @(Get-Process | Where-Object { $_.ProcessName -like 'YuanC-Client*' -or $_.ProcessName -like 'WinClient*' })
if ($running.Count -gt 0) {
    Write-Output ('界面试跑没法做:已有客户端进程在运行:' + (($running | ForEach-Object { $_.ProcessName + '#' + $_.Id }) -join ', '))
    exit 3
}

$code = 1
$process = $null
$window = $null
try {
    [IO.Directory]::CreateDirectory($OutDir) | Out-Null
    $target = Join-Path $OutDir 'diag-smoke.json'
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    $shell = New-Object -ComObject Shell.Application
    $before = @(foreach ($w in @($shell.Windows())) { try { [long]$w.HWND } catch { } })

    $process = Start-Process -FilePath $Exe -PassThru
    $byPid = Cond $A::ProcessIdProperty $process.Id
    $window = Wait-For { $A::RootElement.FindFirst($T::Children, $byPid) } 60 '主窗口'
    $label = Wait-For { $window.FindFirst($T::Descendants, (Both (Cond $A::ControlTypeProperty $C::Text) (Cond $A::NameProperty '更新与诊断'))) } 30 '导航项「更新与诊断」'
    Start-Sleep -Seconds 3
    $homeTexts = @(Get-Texts $window)
    Write-Output '== 首页文字'
    $homeTexts
    Save-Shot $window (Join-Path $OutDir 'ui-home.png')
    $marks = @($homeTexts | Where-Object { $_ -like '*测试包*' })
    if ($ExpectTestBuild -and $marks.Count -eq 0) { throw '这是测试包,首页却没有「测试包」字样' }
    if (-not $ExpectTestBuild -and $marks.Count -gt 0) { throw ('这不是测试包,首页却出现了:' + ($marks -join ' / ')) }

    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $nav = $label
    while ($nav -and $nav.Current.ControlType -ne $C::RadioButton) { $nav = $walker.GetParent($nav) }
    if (-not $nav) { throw '没找到「更新与诊断」的导航按钮' }
    $nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
    $button = Wait-For {
        $buttons = $window.FindAll($T::Descendants, (Cond $A::ControlTypeProperty $C::Button))
        foreach ($item in $buttons) { if ($item.Current.Name -like '导出诊断*') { return $item } }
    } 15 '按钮「导出诊断…」'
    if ($ExpectVersion) {
        $shown = @(Get-Texts $window | Where-Object { $_ -eq ('Text:' + $ExpectVersion) })
        if ($shown.Count -eq 0) { throw ('「更新与诊断」页没有显示版本号 ' + $ExpectVersion) }
    }
    $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()

    $isDialog = Both (Cond $A::ControlTypeProperty $C::Window) (Cond $A::NameProperty '导出诊断')
    $dialog = Wait-For {
        $inside = $window.FindFirst($T::Descendants, $isDialog)
        if ($inside) { return $inside }
        $A::RootElement.FindFirst($T::Children, (Both $byPid (Cond $A::NameProperty '导出诊断')))
    } 20 '保存对话框'
    $hDialog = [IntPtr]$dialog.Current.NativeWindowHandle
    $hEdit = Wait-For { $h = [NativeDialog]::FindFileNameEdit($hDialog); if ($h -ne [IntPtr]::Zero) { $h } } 15 '保存对话框里的文件名框'
    # 文件名不改,照界面给的默认名存到桌面(和真人点一下保存一样),写出后再挪进输出目录。
    $defaultName = [NativeDialog]::GetText($hEdit)
    Write-Output ('== 保存对话框的默认文件名:' + $defaultName)
    if ($defaultName -notmatch '^澳洲出口客户端-诊断-\d{8}-\d{6}(\.json)?$') { throw ('保存对话框的默认文件名不对:' + $defaultName) }
    if ($defaultName -notlike '*.json') { $defaultName += '.json' }
    $written = Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) $defaultName
    $hSave = [NativeDialog]::FindChild($hDialog, 'Button', 1)
    if ($hSave -eq [IntPtr]::Zero) { throw '保存对话框里没找到「保存」按钮' }
    [NativeDialog]::PostMessage($hSave, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Wait-For { Test-Path -LiteralPath $written } 60 ('导出的文件 ' + $written) | Out-Null
    $done = Wait-For { @(Get-Texts $window | Where-Object { $_ -like 'Text:已导出：*' }) | Select-Object -First 1 } 30 '界面上「已导出：」开头的结果提示'
    Write-Output ('== 界面给出的结果:' + $done)

    # 导出成功后界面会打开所在文件夹;只关这次新开出来的窗口,原来就开着的不碰。
    $closed = 0
    $deadline = (Get-Date).AddSeconds(10)
    while ($closed -eq 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        foreach ($w in @($shell.Windows())) {
            try { if ($before -notcontains [long]$w.HWND) { $w.Quit(); $closed++ } } catch { }
        }
    }
    Move-Item -LiteralPath $written -Destination $target -Force
    Save-Shot $window (Join-Path $OutDir 'ui-update.png')

    $item = Get-Item -LiteralPath $target
    $json = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($json.schema -ne 1) { throw ('导出的文件 schema 不是 1:' + $json.schema) }
    if ($ExpectVersion -and $json.ui.version -ne $ExpectVersion) { throw ('导出的文件里界面版本是 ' + $json.ui.version + ',应为 ' + $ExpectVersion) }
    Write-Output ('界面试跑通过:' + $Exe + ';导出文件 ' + $item.Length + ' 字节,在 ' + $target)
    $code = 0
} catch {
    Write-Output ('界面试跑没通过:' + $_.Exception.Message)
    try { if ($window) { Write-Output '== 没通过时窗口里的文字'; Get-Texts $window } } catch { }
} finally {
    # 结束后等它真的退出,免得紧接着的下一次试跑撞上「已有客户端进程」。
    try {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        if ($process) { $process.WaitForExit(10000) | Out-Null }
    } catch { }
}
exit $code
