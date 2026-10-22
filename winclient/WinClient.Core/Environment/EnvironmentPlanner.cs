using System.Text;
using System.Text.RegularExpressions;

// 避免 Environment 命名空间遮蔽既有代码使用的 System.Environment。
namespace WinClient.Core.EnvironmentSupport;

public sealed record EnvironmentTarget
{
    public string TimeZoneId { get; }
    private readonly string[] languages;
    public string[] Languages => (string[])languages.Clone();

    public EnvironmentTarget(string TimeZoneId, string[] Languages)
    {
        if (TimeZoneId is null || !Regex.IsMatch(TimeZoneId, @"\A[A-Za-z0-9 .()+/-]{1,64}\z"))
            throw new ArgumentException("时区标识格式不正确。", nameof(TimeZoneId));
        if (Languages is null || Languages.Length is < 1 or > 8 ||
            Languages.Any(value => value is null || !Regex.IsMatch(value, @"\A[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*\z")))
            throw new ArgumentException("首选语言必须为一到八个有效语言标识。", nameof(Languages));
        this.TimeZoneId = TimeZoneId;
        languages = (string[])Languages.Clone();
    }
}

/// <summary>只生成脚本文本；本类不读取或修改主机环境。</summary>
public static class EnvironmentPlanner
{
    public const string ChromeKey = @"HKLM:\SOFTWARE\Policies\Google\Chrome";
    public const string EdgeKey = @"HKLM:\SOFTWARE\Policies\Microsoft\Edge";
    public const string TzServiceKey = @"HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate";

    private static StringBuilder Header(string? statePath = null)
    {
        var script = new StringBuilder("$ErrorActionPreference = 'Stop'\n");
        if (statePath is not null)
        {
            script.AppendLine("$statePath = " + Quote(Path.GetFullPath(statePath)));
            script.AppendLine("function Write-State($value) { $temp = $statePath + '.tmp'; $value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temp -Encoding UTF8; Move-Item -LiteralPath $temp -Destination $statePath -Force }");
        }
        script.AppendLine("$chromeKey = " + Quote(ChromeKey));
        script.AppendLine("$edgeKey = " + Quote(EdgeKey));
        script.AppendLine("$tzServiceKey = " + Quote(TzServiceKey));
        script.AppendLine(@"$forcedKey = $chromeKey + '\ForcedLanguages'");
        script.AppendLine("$chromeNames = @('WebRtcIPHandling', 'DefaultGeolocationSetting')");
        script.AppendLine("$edgeNames = @('DefinePreferredLanguages', 'WebRtcLocalhostIpHandling', 'DefaultGeolocationSetting')");
        return script;
    }

    // 注册表值名来自固定清单；不存在与读取失败必须区分，以免丢失恢复依据。
    private const string ReadHelpers = """
        function Read-Value($path, $name) {
          if (-not (Test-Path -LiteralPath $path)) { return @{ present=$false; kind='String'; value=$null } }
          $item = Get-Item -LiteralPath $path
          $properties = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue -ErrorVariable readErrors
          if ($readErrors) { throw '无法读取浏览器策略原值。' }
          $present = $item.GetValueNames() -contains $name
          if (-not $present) { return @{ present=$false; kind='String'; value=$null } }
          $kind = [string]$item.GetValueKind($name)
          if ($kind -notin @('String','DWord')) { throw '浏览器策略原值类型不支持，未更改设置。' }
          return @{ present=$true; kind=$kind; value=$properties.PSObject.Properties[$name].Value }
        }
        function Read-Values($path, $names) {
          $values = @{}
          foreach ($name in $names) { $values[$name] = Read-Value $path $name }
          return $values
        }
        function Read-ForcedLanguages {
          $values = @{}
          $present = Test-Path -LiteralPath $forcedKey
          if ($present) {
            $item = Get-Item -LiteralPath $forcedKey
            foreach ($name in $item.GetValueNames()) {
              if ([string]$item.GetValueKind($name) -ne 'String') { throw '浏览器语言策略原值类型不支持，未更改设置。' }
              $values[$name] = $item.GetValue($name)
            }
          }
          return @{ present=$present; values=$values }
        }
        """;

    public static string ApplyScript(EnvironmentTarget target, string statePath)
    {
        var script = Header(statePath);
        script.AppendLine(ReadHelpers);
        script.AppendLine($$"""
            if (Test-Path -LiteralPath $statePath) {
              $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
              if ($previous.schema -ne 1 -or $null -eq $previous.original) { throw '环境恢复记录无效，未更改设置。' }
              $original = $previous.original
              $tzBefore = $original.time_zone
            } else {
              $tzBefore = (& tzutil /g).Trim()
              if ($LASTEXITCODE -ne 0 -or -not $tzBefore) { throw '无法读取系统时区。' }
              $autoStart = (Get-ItemProperty -LiteralPath $tzServiceKey -ErrorAction SilentlyContinue).Start
              $original = @{
                time_zone=$tzBefore; tzautoupdate_start=$autoStart
                chrome=@{ present=(Test-Path -LiteralPath $chromeKey); values=(Read-Values $chromeKey $chromeNames) }
                edge=@{ present=(Test-Path -LiteralPath $edgeKey); values=(Read-Values $edgeKey $edgeNames) }
                forced_languages=(Read-ForcedLanguages)
              }
            }
            $state = [pscustomobject]@{
              schema=1; applied = $false; original=$original
              target=@{ time_zone={{Quote(target.TimeZoneId)}}; languages=@({{string.Join(",", target.Languages.Select(Quote))}}) }
              written_at=[DateTime]::UtcNow.ToString('o'); verify_failed=$null
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($statePath)) | Out-Null
            Write-State $state
            Set-ItemProperty -LiteralPath $tzServiceKey -Name Start -Value 4 -Type DWord
            Stop-Service tzautoupdate -ErrorAction SilentlyContinue
            & tzutil /s {{Quote(target.TimeZoneId)}}
            if ($LASTEXITCODE -ne 0) { throw '时区切换命令失败。' }
            $tzAfter = (& tzutil /g).Trim()
            if ($LASTEXITCODE -ne 0) { throw '无法复核系统时区。' }
            if ($tzAfter -ne {{Quote(target.TimeZoneId)}}) { $state.verify_failed='time_zone'; Write-State $state; exit 4 }
            foreach ($path in @($chromeKey, $edgeKey, $forcedKey)) {
              if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
            }
            foreach ($name in (Get-Item -LiteralPath $forcedKey).GetValueNames()) {
              Remove-ItemProperty -LiteralPath $forcedKey -Name $name
            }
            """);
        var languages = target.Languages;
        for (var i = 0; i < languages.Length; i++)
            script.AppendLine($"Set-ItemProperty -LiteralPath $forcedKey -Name '{i + 1}' -Value {Quote(languages[i])} -Type String");
        script.AppendLine($$"""
            Set-ItemProperty -LiteralPath $chromeKey -Name WebRtcIPHandling -Value 'default_public_interface_only' -Type String
            Set-ItemProperty -LiteralPath $chromeKey -Name DefaultGeolocationSetting -Value 2 -Type DWord
            Set-ItemProperty -LiteralPath $edgeKey -Name DefinePreferredLanguages -Value {{Quote(string.Join(",", languages))}} -Type String
            Set-ItemProperty -LiteralPath $edgeKey -Name WebRtcLocalhostIpHandling -Value 'default_public_interface_only' -Type String
            Set-ItemProperty -LiteralPath $edgeKey -Name DefaultGeolocationSetting -Value 2 -Type DWord
            $state.applied = $true
            Write-State $state
            ConvertTo-Json -Compress @{ time_zone_before=$tzBefore; time_zone_after=$tzAfter; policies_written=6 }
            exit 0
            """);
        return script.ToString();
    }

    public static string RestoreScript(string statePath)
    {
        var script = Header(statePath);
        script.AppendLine("""
            if (-not (Test-Path -LiteralPath $statePath)) { exit 0 }
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $original = $state.original
            if ($state.schema -ne 1 -or $null -eq $original -or $null -eq $original.chrome -or $null -eq $original.edge -or $null -eq $original.forced_languages) {
              throw '环境恢复记录无效，原值记录已保留。'
            }
            if ($original.time_zone) {
              & tzutil /s $original.time_zone
              if ($LASTEXITCODE -ne 0) { throw '时区未能恢复。' }
              $restoredZone = (& tzutil /g).Trim()
              if ($LASTEXITCODE -ne 0 -or $restoredZone -ne $original.time_zone) { throw '时区恢复复核失败。' }
            }
            if ($null -ne $original.tzautoupdate_start) {
              Set-ItemProperty -LiteralPath $tzServiceKey -Name Start -Value $original.tzautoupdate_start -Type DWord
              if ($original.tzautoupdate_start -eq 3) { Start-Service tzautoupdate -ErrorAction SilentlyContinue }
            }
            foreach ($browser in @('chrome', 'edge')) {
              if ($browser -eq 'chrome') { $path=$chromeKey; $names=$chromeNames } else { $path=$edgeKey; $names=$edgeNames }
              $saved = $original.$browser
              foreach ($name in $names) {
                $entry = $saved.values.$name
                if ($null -eq $entry -or $entry.kind -notin @('String','DWord')) { throw '浏览器策略恢复记录无效。' }
                if ($entry.present) {
                  if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                  Set-ItemProperty -LiteralPath $path -Name $name -Value $entry.value -Type $entry.kind
                } elseif ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).GetValueNames() -contains $name) {
                  Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue -ErrorVariable removeErrors
                  if ($removeErrors) { throw '浏览器策略未能恢复。' }
                }
              }
            }
            $forced = $original.forced_languages
            if (-not $forced.present) {
              if (Test-Path -LiteralPath $forcedKey) {
                if ((Get-Item -LiteralPath $forcedKey).SubKeyCount -ne 0) { throw '语言策略子键发生变化，恢复记录已保留。' }
                Remove-Item -LiteralPath $forcedKey -Force
              }
            } else {
              if (-not (Test-Path -LiteralPath $forcedKey)) { New-Item -Path $forcedKey -Force | Out-Null }
              foreach ($name in (Get-Item -LiteralPath $forcedKey).GetValueNames()) {
                Remove-ItemProperty -LiteralPath $forcedKey -Name $name
              }
              foreach ($property in $forced.values.PSObject.Properties) {
                Set-ItemProperty -LiteralPath $forcedKey -Name $property.Name -Value $property.Value -Type String
              }
            }
            foreach ($browser in @('chrome', 'edge')) {
              if ($browser -eq 'chrome') { $path=$chromeKey } else { $path=$edgeKey }
              if (-not $original.$browser.present -and (Test-Path -LiteralPath $path)) {
                $key = Get-Item -LiteralPath $path
                if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { Remove-Item -LiteralPath $path }
              }
            }
            Remove-Item -LiteralPath $statePath
            exit 0
            """);
        return script.ToString();
    }

    public static string InspectScript()
    {
        var script = Header();
        script.AppendLine("""
            function Current-Value($path, $name) {
              $item = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
              if ($null -eq $item) { return $null }
              return $item.PSObject.Properties[$name].Value
            }
            $languages = @()
            if (Test-Path -LiteralPath $forcedKey) {
              $key = Get-Item -LiteralPath $forcedKey
              $languages = @($key.GetValueNames() | Sort-Object { if ($_ -match '^\d+$') { [long]$_ } else { [long]::MaxValue } }, { $_ } | ForEach-Object { $key.GetValue($_) })
            }
            $timeZone = (& tzutil /g).Trim()
            if ($LASTEXITCODE -ne 0) { throw '无法读取系统时区。' }
            $current = @{
              time_zone=$timeZone
              tzautoupdate_start=(Current-Value $tzServiceKey 'Start')
              chrome=@{ forced_languages=$languages; WebRtcIPHandling=(Current-Value $chromeKey 'WebRtcIPHandling'); DefaultGeolocationSetting=(Current-Value $chromeKey 'DefaultGeolocationSetting') }
              edge=@{ DefinePreferredLanguages=(Current-Value $edgeKey 'DefinePreferredLanguages'); WebRtcLocalhostIpHandling=(Current-Value $edgeKey 'WebRtcLocalhostIpHandling'); DefaultGeolocationSetting=(Current-Value $edgeKey 'DefaultGeolocationSetting') }
            }
            ConvertTo-Json -Compress -Depth 5 -InputObject $current
            """);
        return script.ToString();
    }

    private static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
}
