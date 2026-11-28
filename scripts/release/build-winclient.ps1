param([string]$Version, [switch]$TestBuild, [switch]$UiSmoke)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    if ([string]::IsNullOrWhiteSpace($Version)) {
        [xml]$props = Get-Content -LiteralPath (Join-Path $root 'winclient/Directory.Build.props') -Raw -Encoding UTF8
        $Version = [string]$props.Project.PropertyGroup.Version
    }
    if ($Version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z') {
        throw '客户端版本必须是有效的三段版本号，可附预发布标识。'
    }
    $project = Join-Path $root 'winclient/WinClient.App'
    $publish = Join-Path $root 'build/winclient/publish/WinClient.App/release_win-x64'
    $release = Join-Path $root 'build/release'
    [IO.Directory]::CreateDirectory($publish) | Out-Null
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = 'dotnet'
    $start.Arguments = 'publish "' + $project + '" -c Release -p:PublishProfile=SingleFile -p:Version=' + $Version + ' -o "' + $publish + '" --nologo'
    # 测试包:把开关写进程序集元数据,客户端据此关闭断网保护、出口核验不了自动断开、开机不自动连接。
    if ($TestBuild) { $start.Arguments += ' -p:YuanCTestBuild=true' }
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        # Read both pipes concurrently so verbose builds cannot deadlock.
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [Console]::Out.Write($stdout.Result)
        [Console]::Error.Write($stderr.Result)
        if ($process.ExitCode -ne 0) { throw "客户端发布失败，dotnet 退出码：$($process.ExitCode)" }
    } finally { $process.Dispose() }

    $unexpected = @(Get-ChildItem -LiteralPath $publish -Recurse -File | Where-Object { $_.Extension -notin @('.exe', '.pdb') })
    if ($unexpected.Count -gt 0) { throw ('单文件发布检查失败，目录仍含外置依赖或数据文件：' + ($unexpected.Name -join ', ')) }
    $executable = Join-Path $publish 'WinClient.App.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw '发布结果缺少客户端程序。' }
    # 与客户端自动更新接收的防呆线(UpdateManifest.MaxPayloadBytes,1 GiB)同数,超过它的包客户端不收。
    if ((Get-Item -LiteralPath $executable).Length -gt 1GB) { throw '客户端超过 1GB，自动更新不会接收，请先查是什么撑大了包。' }
    if ($UiSmoke) {
        # 交出去之前先自动点一遍界面;没通过或没法试都不出包。
        $smokeVersion = ($Version -split '\+')[0]
        & (Join-Path $PSScriptRoot 'ui-smoke.ps1') -Exe $executable -OutDir (Join-Path $root 'build/ui-smoke') -ExpectVersion $smokeVersion -ExpectTestBuild:$TestBuild
        if ($LASTEXITCODE -ne 0) { throw "界面试跑没有通过（退出码 $LASTEXITCODE），没有出包。" }
    }
    [IO.Directory]::CreateDirectory($release) | Out-Null
    $name = 'YuanC-Client-' + $Version + $(if ($TestBuild) { '-test' } else { '' }) + '.exe'
    $destination = Join-Path $release $name
    Copy-Item -LiteralPath $executable -Destination $destination -Force
    $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(($destination + '.sha256'), ($hash + '  ' + $name + "`n"), (New-Object Text.UTF8Encoding($false)))
    Write-Host "发布完成：$destination"
    Write-Host "大小（字节）：$((Get-Item -LiteralPath $destination).Length)"
    Write-Host "SHA256：$hash"
    if ($TestBuild) { Write-Host '测试包：断网保护已关闭，不能交给客户。' }
} catch {
    [Console]::Error.WriteLine('Windows 客户端出包失败：' + $_.Exception.Message)
    exit 1
}
