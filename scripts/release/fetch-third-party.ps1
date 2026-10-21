param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

function Assert-Hash([string]$Path, [string]$Expected, [string]$Label) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
        throw "$Label 校验失败：SHA256 与清单不一致，请核对官方原包；不会修改清单或更换来源。"
    }
}

try {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../winclient/third_party'))
    $manifest = Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $items = @($manifest.items)
    if ($items.Count -ne 2 -or (@($items.file | Sort-Object) -join ',') -cne 'sing-box.exe,wintun.dll') {
        throw '第三方清单必须恰好包含 sing-box.exe 和 wintun.dll。'
    }
    $cache = Join-Path $root 'cache'
    $bin = Join-Path $root 'bin'
    [IO.Directory]::CreateDirectory($cache) | Out-Null
    [IO.Directory]::CreateDirectory($bin) | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $files = @()
    foreach ($item in $items) {
        if ($item.zip_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $item.file_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "第三方清单哈希格式无效：$($item.file)"
        }
        $uri = [Uri]$item.url
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https') { throw '第三方下载地址必须是完整 HTTPS 地址。' }
        $zipPath = Join-Path $cache ([IO.Path]::GetFileName($uri.AbsolutePath))
        if (Test-Path -LiteralPath $zipPath) {
            Assert-Hash $zipPath $item.zip_sha256 "缓存压缩包 $($item.name)"
            Write-Host "使用已校验缓存（不联网）：$($item.name)"
        } else {
            $download = $zipPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Write-Host "下载固定来源：$($item.url)"
                Invoke-WebRequest -UseBasicParsing -Uri $item.url -OutFile $download -TimeoutSec 180
                Assert-Hash $download $item.zip_sha256 "下载压缩包 $($item.name)"
                [IO.File]::Move($download, $zipPath)
            } finally {
                if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Force }
            }
        }
        $destination = Join-Path $bin $item.file
        if ((Test-Path -LiteralPath $destination) -and
            (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $item.file_sha256) {
            Write-Host "保留已校验文件（零写入）：$($item.file)"
        } else {
          $temporary = $destination + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
          try {
            $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
            try {
                $member = $archive.GetEntry($item.zip_member)
                if ($null -eq $member) { throw "压缩包缺少清单指定成员：$($item.zip_member)" }
                [IO.Compression.ZipFileExtensions]::ExtractToFile($member, $temporary)
            } finally { $archive.Dispose() }
            Assert-Hash $temporary $item.file_sha256 "解包文件 $($item.file)"
            Move-Item -LiteralPath $temporary -Destination $destination -Force
            Assert-Hash $destination $item.file_sha256 "输出文件 $($item.file)"
          } finally {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
          }
        }
        $files += [ordered]@{ file = $item.file; sha256 = $item.file_sha256; resource = 'YuanC.Kernel.' + $item.file }
    }
    $kernelVersion = ($items | Where-Object { $_.name -ceq 'sing-box' }).version
    if ($kernelVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') { throw '内核版本格式无效。' }
    $kernel = [ordered]@{ version = $kernelVersion; files = $files } | ConvertTo-Json -Depth 5
    $kernelPath = Join-Path $bin 'kernel-manifest.json'
    if (-not [IO.File]::Exists($kernelPath) -or [IO.File]::ReadAllText($kernelPath) -cne $kernel) {
        [IO.File]::WriteAllText($kernelPath, $kernel, (New-Object Text.UTF8Encoding($false)))
    }
    Write-Host '第三方组件校验完成，内核清单已生成。'
} catch {
    [Console]::Error.WriteLine('获取连接内核失败：' + $_.Exception.Message)
    exit 1
}
