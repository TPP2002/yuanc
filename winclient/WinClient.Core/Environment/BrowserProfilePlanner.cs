using System.Text.Json;

namespace WinClient.Core.EnvironmentSupport;

/// <summary>只生成当前用户脚本文本并解释结果，不读写主机。</summary>
public static class BrowserProfilePlanner
{
    public const string AcceptLanguages = "en-AU,en";
    public const string WebRtcPolicy = "default_public_interface_only";
    public const string ProfileRoot = @"YuanC\Browser";
    public const string ShortcutPrefix = "澳洲专用 ";

    public static string Script() => $$$"""
        $ErrorActionPreference = 'Stop'
        $desktop = [Environment]::GetFolderPath('Desktop')
        $root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) '{{{ProfileRoot}}}'
        function Find-Browser($exe) {
          foreach ($key in @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exe",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exe",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$exe"
          )) {
            $path = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).'(default)'
            if ($path -and (Test-Path -LiteralPath $path)) { return $path }
          }
          $paths = if ($exe -eq 'chrome.exe') {
            @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
              "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
              "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
          } elseif ($exe -eq 'msedge.exe') {
            @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
              "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
          } else { @() }
          foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path) { return $path }
          }
          return $null
        }
        $created = @()
        $missing = @()
        $kept = @()
        foreach ($browser in @(@{ name='Chrome'; exe='chrome.exe' }, @{ name='Edge'; exe='msedge.exe' })) {
          $exe = Find-Browser $browser.exe
          if (-not $exe) { $missing += $browser.name; continue }
          $profile = Join-Path $root $browser.name
          [IO.Directory]::CreateDirectory((Join-Path $profile 'Default')) | Out-Null
          $prefFile = Join-Path $profile 'Default\Preferences'
          if (Test-Path -LiteralPath $prefFile) { $kept += $browser.name } else {
            $preferences = '{"intl":{"accept_languages":"{{{AcceptLanguages}}}"},"webrtc":{"ip_handling_policy":"{{{WebRtcPolicy}}}"}}'
            $encoding = New-Object Text.UTF8Encoding($false)
            [IO.File]::WriteAllText($prefFile, $preferences, $encoding)
          }
          $shell = New-Object -ComObject WScript.Shell
          $shortcut = $shell.CreateShortcut((Join-Path $desktop ('{{{ShortcutPrefix}}}' + $browser.name + '.lnk')))
          $shortcut.TargetPath = $exe
          $shortcut.Arguments = '--user-data-dir="' + $profile + '" --disable-quic --no-first-run --no-default-browser-check'
          $shortcut.WorkingDirectory = [IO.Path]::GetDirectoryName($exe)
          $shortcut.IconLocation = $exe + ',0'
          $shortcut.Description = '澳洲专用浏览器:只登录目标平台账号'
          $shortcut.Save()
          $created += $browser.name
        }
        ConvertTo-Json -Compress @{ created=@($created); missing=@($missing); kept=@($kept) }
        exit 0
        """;

    public static string Describe(string? output)
    {
        const string incomplete = "创建快捷方式未完成,请联系管理员。";
        var line = output?.Split('\n').LastOrDefault(value => !string.IsNullOrWhiteSpace(value));
        if (line is null) return incomplete;
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !(root.TryGetProperty("created", out _) || root.TryGetProperty("missing", out _) || root.TryGetProperty("kept", out _)))
                return incomplete;
            var created = Names(root, "created");
            var missing = Names(root, "missing");
            var kept = Names(root, "kept");
            if (created.Length == 0) return "未找到 Chrome 或 Edge,请先安装其中一个再试。";
            return "已在桌面创建:" + string.Join("、", created.Select(name => ShortcutPrefix + name)) + "。"
                + string.Concat(missing.Select(name => $"未找到 {name}。"))
                + string.Concat(kept.Select(name => $"{name} 的专用配置档已存在,保留原设置。"))
                + "专用档只登录目标平台账号,日常上网仍用原来的浏览器。";
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        { return incomplete; }
    }

    private static string[] Names(JsonElement root, string key)
    {
        if (!root.TryGetProperty(key, out var value)) return [];
        if (value.ValueKind == JsonValueKind.String) return [value.GetString()!];
        return value.EnumerateArray().Select(item => item.GetString() ?? throw new JsonException()).ToArray();
    }
}
