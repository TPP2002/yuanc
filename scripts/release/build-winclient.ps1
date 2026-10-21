param([string]$Version)
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
    if ((Get-Item -LiteralPath $executable).Length -ge 200MB) { throw '客户端大小必须小于 200MB。' }
    [IO.Directory]::CreateDirectory($release) | Out-Null
    $name = 'YuanC-Client-' + $Version + '.exe'
    $destination = Join-Path $release $name
    Copy-Item -LiteralPath $executable -Destination $destination -Force
    $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(($destination + '.sha256'), ($hash + '  ' + $name + "`n"), (New-Object Text.UTF8Encoding($false)))
    Write-Host "发布完成：$destination"
    Write-Host "大小（字节）：$((Get-Item -LiteralPath $destination).Length)"
    Write-Host "SHA256：$hash"
} catch {
    [Console]::Error.WriteLine('Windows 客户端出包失败：' + $_.Exception.Message)
    exit 1
}
