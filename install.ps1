# NetGuard 安装/卸载（需管理员）。只复制文件并注册状态核对任务，不会自动开启断网保护。
param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '请以管理员身份运行。' }
$Target = Join-Path $env:ProgramData 'NetGuard'
$TaskName = 'NetGuard-Status'
$PowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

if ($Uninstall) {
    if (Test-Path (Join-Path $Target 'netguard.ps1')) {
        & $PowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Target 'netguard.ps1') -Action disable
        if ($LASTEXITCODE -ne 0) { throw '移除规则失败，已停止卸载并保留文件与任务。' }
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'NetGuard 已卸载，所有规则已移除。'
    return
}

if ((Test-Path $Target) -and ((Get-Item $Target).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '目标目录不能是重解析点。' }
New-Item -ItemType Directory -Path $Target -Force | Out-Null
# Back up the installed scripts/config; updating never invokes Apply or changes WFP rules.
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
foreach ($Name in @('netguard.ps1','netguard_wfp.cs','config.json','state.json')) {
    $Existing = Join-Path $Target $Name
    if (Test-Path -LiteralPath $Existing) {
        if ((Get-Item -LiteralPath $Existing).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '安装目标文件不能是重解析点。' }
        Copy-Item -LiteralPath $Existing -Destination "$Existing.bak-$Stamp"
    }
}
# 只有 SYSTEM/管理员可写，普通用户只读，防止被普通程序篡改后借 UAC 提权
$Acl = New-Object Security.AccessControl.DirectorySecurity
$Acl.SetAccessRuleProtection($true, $false)
$Acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($Sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($Sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $Target -AclObject $Acl
foreach ($File in @('netguard.ps1', 'netguard_wfp.cs')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot "admin\$File") -Destination $Target -Force }

$FlClash = Join-Path $env:LOCALAPPDATA 'Programs\FlClash'
$Apps = @('FlClashCore.exe', 'FlClash.exe') | ForEach-Object { Join-Path $FlClash $_ } | Where-Object { Test-Path $_ }
if (-not ($Apps | Where-Object { $_ -like '*FlClashCore.exe' })) { throw "找不到 $FlClash\FlClashCore.exe" }
$Guard = Join-Path $env:LOCALAPPDATA 'Programs\ClaudeGuard\data\config.json'
$Whitelist = @()
if (Test-Path $Guard) { $Whitelist = @((Get-Content -LiteralPath $Guard -Raw -Encoding UTF8 | ConvertFrom-Json).allowed_ips) }
$Config = [ordered]@{
    allow_apps = @($Apps); whitelist = @($Whitelist)
    tun_v4 = '198.18.0.0'; tun_v4_prefix = 16; tun_v6 = 'fdfe:dcba:9876::'; tun_v6_prefix = 48
    check_url = 'https://www.cloudflare.com/cdn-cgi/trace'; claude_check_url = 'https://claude.ai/cdn-cgi/trace'
}
if (-not (Test-Path -LiteralPath (Join-Path $Target 'config.json'))) {
    [IO.File]::WriteAllText((Join-Path $Target 'config.json'), ($Config | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
}

# SYSTEM 常驻 watch 循环：每 10 秒自动防护检查并写 status.json（普通用户无权直接读 WFP）。
# 开机触发 + 每分钟触发（IgnoreNew）= 看门狗：循环在跑时触发被忽略；意外退出时 1 分钟内拉起。不设运行时长上限。
# 更新时必须先停掉旧循环，否则旧代码会继续运行。
if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName }
$Action = New-ScheduledTaskAction -Execute $PowerShell -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Target 'netguard.ps1') + '" -Action watch')
$Triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)))
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$Task = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Triggers -Settings $Settings -Principal $Task -Force | Out-Null
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Target 'netguard.ps1') -Action status
if ($LASTEXITCODE -ne 0) { throw '脚本已复制，但状态核对失败；现有 WFP 规则未改动，请查看日志。' }
Start-ScheduledTask -TaskName $TaskName   # 立即启动新循环，不等下一分钟
Write-Host "NetGuard 管理脚本已更新到 $Target；原有配置和保护状态保持不变。"
