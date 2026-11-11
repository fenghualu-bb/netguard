# NetGuard 1.3.4 管理脚本（需管理员/SYSTEM）。安装后从 C:\ProgramData\NetGuard 运行，普通用户无法改写。
#   enable          开启全局断网保护（先检查代理在工作，生效后再自检，失败自动回滚）
#   disable         关闭全局断网保护（也会解除真实 IP 模式的 Claude 封锁）
#   claude-block    真实 IP 模式：强制封锁 Claude 程序联网
#   claude-unblock  退出真实 IP 模式：解除 Claude 封锁（先确认出口已回到白名单 IP）
#   status          只核对并写入 status.json
#   watch           SYSTEM 计划任务：常驻循环，每 10 秒自动防护检查一次（发现泄露风险则锁定 Claude），并写状态
#   release         解除自动防护锁定（先重新检查，全部通过才解除）
#   guard-on/off    开启 / 关闭自动防护
param([Parameter(Mandatory=$true)][ValidateSet('enable','disable','claude-block','claude-unblock','status','watch','release','guard-on','guard-off')][string]$Action)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Config = Get-Content -LiteralPath (Join-Path $Root 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$StateFile = Join-Path $Root 'state.json'
$StatusFile = Join-Path $Root 'status.json'
$LogFile = Join-Path $Root 'netguard.log'
$GuardFile = Join-Path $Root 'guard.json'      # 自动防护运行状态（连续异常计数、锁定原因）
$EventsFile = Join-Path $Root 'events.jsonl'   # 保护记录：每行一条 JSON，工作台「保护记录」页读取
Add-Type -Path (Join-Path $Root 'netguard_wfp.cs')

function Log([string]$Text) { Add-Content -LiteralPath $LogFile -Encoding UTF8 -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Action] $Text" }
function Read-State {
    if (Test-Path -LiteralPath $StateFile) { return Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json }
    return [pscustomobject]@{ killswitch = $false; claude_block = $false }
}
function Write-Json($Path, $Value) {
    $Temp = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($Temp, ($Value | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $Temp -Destination $Path -Force
}
# Claude 程序清单取自 ClaudeGuard 受保护的 manifest（同样只有管理员可写），随 ClaudeGuard 修复自动更新
function Claude-Programs {
    $List = @()
    foreach ($M in Get-ChildItem -Path (Join-Path $env:ProgramData 'ClaudeGuardNetwork') -Filter manifest.json -Recurse -ErrorAction SilentlyContinue) {
        $List += @((Get-Content -LiteralPath $M.FullName -Raw | ConvertFrom-Json).programs)
    }
    return @($List | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique)
}
function Proxy-Apps { return @($Config.allow_apps | Where-Object { Test-Path -LiteralPath $_ }) }
function Egress([string]$Url) {
    try {
        $R = Invoke-WebRequest -UseBasicParsing -TimeoutSec 8 -Uri $Url
        $Text = if ($R.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($R.Content) } else { $R.Content }
        if ($Text -match '(?m)^ip=(.+)$') { return $Matches[1].Trim() }
        return $Text.Trim()
    } catch { return $null }
}
function Apply($State) {
    # 外层 @() 不能省：PowerShell 会把 if/函数返回的空数组变成 $null
    [string[]]$Claude = @(if ($State.claude_block) { Claude-Programs })
    if ($State.claude_block -and $Claude.Count -eq 0) { throw '找不到 Claude 程序清单（ClaudeGuard 网络助手 manifest），无法封锁。' }
    [string[]]$Apps = @(if ($State.killswitch) { Proxy-Apps })
    if ($State.killswitch -and -not ($Apps | Where-Object { $_ -like '*flclashcore.exe' })) { throw '找不到 FlClashCore.exe，拒绝开启（否则代理自身也会被断网）。' }
    $W = [NetGuardWfp]::new()
    try { $W.Apply([bool]$State.killswitch, $Config.tun_v4, [int]$Config.tun_v4_prefix, $Config.tun_v6, [int]$Config.tun_v6_prefix, $Apps, $Claude) }
    finally { $W.Dispose() }
}
function Get-RuleHealth([string[]]$Names, $State) {
    $BaseExpected = @(); $BlockExpected = @()
    foreach ($Tag in @('v4','v6')) {
        if ($State.killswitch) {
            $BaseExpected += @("$Tag|NetGuard permit TUN $Tag", "$Tag|NetGuard block DNS outside TUN $Tag", "$Tag|NetGuard permit loopback $Tag", "$Tag|NetGuard permit LAN/link-local $Tag", "$Tag|NetGuard block all other $Tag")
            foreach ($App in @(Proxy-Apps)) { $BaseExpected += @("$Tag|NetGuard permit proxy app $App") }
        }
        if ($State.claude_block) { foreach ($App in @(Claude-Programs)) { $BlockExpected += @("$Tag|NetGuard real-ip block $App") } }
    }
    $BlockActual = @($Names | Where-Object { $_ -match '^(v4|v6)\|NetGuard real-ip block .+' })
    $BaseActual = @($Names | Where-Object { $_ -notmatch '^(v4|v6)\|NetGuard real-ip block .+' })
    $ActualBaseCounts = @($BaseActual | Group-Object | ForEach-Object { "$($_.Name)|$($_.Count)" } | Sort-Object)
    $ExpectedBaseCounts = @($BaseExpected | Group-Object | ForEach-Object { "$($_.Name)|$($_.Count)" } | Sort-Object)
    $BaseMatch = ($ActualBaseCounts.Count -eq $ExpectedBaseCounts.Count) -and (($ActualBaseCounts -join "`n") -ceq ($ExpectedBaseCounts -join "`n"))
    $Covered = 0
    foreach ($Group in @($BlockExpected | Group-Object)) {
        $Present = @($BlockActual | Where-Object { $_ -ceq $Group.Name }).Count
        $Covered += [Math]::Min($Present, $Group.Count)
    }
    $Extra = $BlockActual.Count - $Covered
    # Retaining additional DENY rules for older versions cannot weaken isolation.
    $ClaudeComplete = if ($State.claude_block) { $BlockExpected.Count -gt 0 -and $Covered -eq $BlockExpected.Count } else { $BlockActual.Count -eq 0 }
    $Integrity = $BaseMatch -and $ClaudeComplete
    $ExpectedCount = $BaseExpected.Count + $BlockExpected.Count
    if ($State.claude_block) { $ExpectedCount += $Extra }
    return [pscustomobject]@{
        integrity_ok=[bool]$Integrity; killswitch_complete=[bool]($State.killswitch -and $BaseMatch)
        claude_block_complete=[bool]$ClaudeComplete; expected_filter_count=$ExpectedCount
        active_killswitch=[bool]($State.killswitch -and $BaseMatch)
        active_claude_block=[bool]($State.claude_block -and $ClaudeComplete)
        base_filter_count=$BaseActual.Count; expected_base_filter_count=$BaseExpected.Count
        required_claude_filter_count=$BlockExpected.Count; covered_claude_filter_count=$Covered
        extra_claude_filter_count=$Extra
    }
}

function Get-CurrentClaudePackage {
    # AllUsers includes Staged/Servicing updates that are not registered for use.
    # Only an Installed registration may advance the protected Desktop identity.
    $Packages = @(Get-AppxPackage -AllUsers -Name Claude -ErrorAction Stop)
    $Installed = @($Packages | Where-Object {
        @($_.PackageUserInformation | Where-Object { [string]$_.InstallState -eq 'Installed' }).Count -gt 0
    })
    $Pkg = $Installed | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $Pkg -or -not $Pkg.InstallLocation) { throw '无法核实已安装的 Claude 桌面版，保持锁定。' }
    return $Pkg
}

function Get-RequiredClaudePrograms {
    $All = @()
    $ConfiguredDesktops = @()
    foreach ($M in Get-ChildItem -Path (Join-Path $env:ProgramData 'ClaudeGuardNetwork') -Filter manifest.json -Recurse -ErrorAction Stop) {
        $Manifest = Get-Content -LiteralPath $M.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        [string[]]$Listed = @($Manifest.programs | Where-Object { $_ })
        [string[]]$Anchors = @($Manifest.paths | Where-Object { $_ })
        if ($Anchors.Count -ne 2 -or -not ($Manifest.request -is [string]) -or -not [IO.Path]::IsPathRooted($Manifest.request)) {
            throw '受保护清单缺少桌面版/CLI 身份，保持锁定。'
        }
        # The protected helper manifest supplies the user's configuration location.
        # Read only the two program paths; never display proxy or subscription fields.
        $ConfigPath = Join-Path ([IO.Path]::GetDirectoryName($Manifest.request)) 'config.json'
        $UserConfig = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not ($UserConfig.desktop_path -is [string]) -or -not $UserConfig.desktop_path -or -not ($UserConfig.cli_path -is [string]) -or -not $UserConfig.cli_path) {
            throw 'ClaudeGuard 未提供确切的桌面版和 CLI 路径，保持锁定。'
        }
        $Configured = @($UserConfig.desktop_path.ToLowerInvariant(), $UserConfig.cli_path.ToLowerInvariant())
        $Trusted = @($Anchors | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
        $Covered = @($Listed | ForEach-Object { $_.ToLowerInvariant() })
        if ($Trusted.Count -ne 2 -or @($Configured | Sort-Object -Unique).Count -ne 2 -or @($Configured | Where-Object { $_ -notin $Trusted }).Count -or @($Trusted | Where-Object { $_ -notin $Covered }).Count) {
            throw '当前桌面版/CLI 与受保护清单不一致；请先修复 ClaudeGuard，保持锁定。'
        }
        $All += $Listed
        $ConfiguredDesktops += $UserConfig.desktop_path.ToLowerInvariant()
    }
    [string[]]$Programs = @($All | Sort-Object -Unique)
    if ($Programs.Count -lt 2 -or @($Programs | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count) {
        throw 'Claude 程序清单缺失或已过期；请先修复 ClaudeGuard，保持锁定。'
    }
    $Pkg = Get-CurrentClaudePackage
    $Desktop = (Join-Path $Pkg.InstallLocation 'app\claude.exe').ToLowerInvariant()
    if ($Desktop -notin $ConfiguredDesktops -or $Desktop -notin @($Programs | ForEach-Object { $_.ToLowerInvariant() })) {
        throw '清单尚未覆盖当前 Store 桌面版，保持锁定。'
    }
    return $Programs
}

function Sync-LockedIsolation($State, $Guard) {
    if (-not $Guard.lockdown) { return $false }
    if (-not $State.killswitch) { throw '断网保护未开启，拒绝自动修复或解除锁定。' }
    [string[]]$Programs = @(Get-RequiredClaudePrograms)
    $Desired = $State.PSObject.Copy(); $Desired.claude_block = $true
    $W = [NetGuardWfp]::new()
    try {
        $Before = Get-RuleHealth @($W.CurrentByLayer()) $Desired
        if (-not $Before.killswitch_complete) { throw '基础断网保护不完整，保持锁定；需先恢复基础保护。' }
        if ($Before.claude_block_complete -and $State.claude_block) { return $false }
        # This method only ADDS missing per-program deny rules. It never deletes
        # existing filters, adds permits or changes the proxy/TUN configuration.
        $Added = $W.EnsureBlockedApps($Programs)
        Get-RequiredClaudePrograms | Out-Null
        $After = Get-RuleHealth @($W.CurrentByLayer()) $Desired
        if (-not $After.integrity_ok) { throw '补充隔离后核验仍未通过，保留已有规则和锁定。' }
    } finally { $W.Dispose() }
    Write-Json $StateFile $Desired
    $State.claude_block = $true
    Add-Event 'isolation_sync' "已补充 $Added 条 Claude 隔离规则；保持锁定，等待手动解除" @([pscustomobject]@{ key='isolation'; text='程序清单变化后的隔离已同步，未自动解锁' }) ([ordered]@{ added=$Added; programs=$Programs.Count })
    return $true
}

# FlClash（mihomo / sing-tun）开启 strict-route 时，会在动态 WFP 会话里添加 "block ipv4 dns" 等规则；
# 内核退出或未启用时规则会消失。这里只读取规则名称，作为“严格路由实际生效”的运行时证据，
# 它独立于配置文件，也不受读取者所在用户目录的影响。
function Get-StrictRouteRuntime {
    $Result = [ordered]@{ checked_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); detected = $false; owner = $null; dns_block = 0; total = 0; names = @(); error = $null }
    try {
        $W = [NetGuardWfp]::new()
        try { [string[]]$Found = @($W.ExternalMatching([string[]]@('ipv4', 'ipv6'))) } finally { $W.Dispose() }
        # sing-tun 写法：CreateDisplayData(TunnelType, "block ipv4 dns")——规则内容在描述里，名称是 TunnelType。
        # TunnelType 是变量：sing-tun 默认 "sing-tun"，FlClash/mihomo 实测为 "Meta"。所以不写死名称，
        # 而是要求同一所有者同时具备严格路由特有的成组规则：阻断 DNS（block）+ 保护内核自身（protect，permit）。
        $Rows = @($Found | ForEach-Object { $P = $_.Split('|', 4); [pscustomobject]@{ action = $P[1]; name = $P[2]; desc = $(if ($P.Count -gt 3) { $P[3] } else { '' }) } })
        $Owners = @($Rows | Where-Object { $_.action -eq 'block' -and $_.desc -match '^block ipv[46] dns$' } | ForEach-Object { $_.name } | Sort-Object -Unique)
        $Owner = $Owners | Where-Object { $O = $_; @($Rows | Where-Object { $_.name -eq $O -and $_.action -eq 'permit' -and $_.desc -match '^protect ipv[46]$' }).Count -gt 0 } | Select-Object -First 1
        $Result.owner = $Owner
        if ($Owner) {
            $Signature = @($Rows | Where-Object { $_.name -eq $Owner })
            $Result.dns_block = @($Signature | Where-Object { $_.action -eq 'block' -and $_.desc -match '^block ipv[46] dns$' }).Count
            $Result.total = $Signature.Count
        }
        $Result.detected = $Result.dns_block -gt 0
        # 只保留去重后的“动作 名称: 描述”样本，便于以后改名时排查；不含地址、端口或程序路径
        $Result.names = @($Rows | ForEach-Object { "$($_.action) $($_.name): $($_.desc)" } | Sort-Object -Unique | Select-Object -First 15)
    } catch { $Result.error = $_.Exception.Message }
    return $Result
}

# ---------------------------------------------------------------- 自动防护（v1.3.0）
# 只有“有泄露风险”的异常才会触发；连续 $GuardConfirm 次（约 20 秒）确认后才动作，避免网络抖动误杀 Claude。
# 动作：WFP 隔离 Claude 程序 + 结束 Claude 进程。解除只能手动（release），且解除前会重新检查。
$GuardConfirm = 2
$GuardInterval = 10
# 开机 / 登录 / 睡眠唤醒宽限期（v1.3.5）：这几分钟里 FlClash、TUN、ClaudeGuard 还没起来属于正常现象。
# 宽限期内只有「高」危异常（出口不在白名单、断网规则不全、隔离不全、Claude 路径过期）才会计数并锁定；
# 「中」危异常（内核 / TUN / 守护 / 助手未就绪）只记录一次、不锁定。此时断网保护规则已在生效，真实 IP 出不去。
$GraceSeconds = 180
$script:ResumeAt = 0      # watch 循环检测到时间跳变（睡眠唤醒）时写入

# 宽限期起点 = 开机、当前用户登录（最早的 explorer 进程）、上次唤醒 三者中最晚的一个。
# 没有任何用户登录时（停在登录界面）始终处于宽限期：此时不可能有 Claude 在运行。
function Get-GraceInfo {
    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $Anchors = @([double]$script:ResumeAt)
    try { $Anchors += ([DateTimeOffset](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime).ToUnixTimeSeconds() } catch {}
    $Explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | ForEach-Object { try { $_.StartTime } catch { $null } } | Where-Object { $_ })
    if (-not $Explorer.Count) { return [pscustomobject]@{ active = $true; until = $Now + $GraceSeconds; anchor = $Now; reason = '尚无用户登录' } }
    $Anchors += ([DateTimeOffset](($Explorer | Sort-Object | Select-Object -First 1))).ToUnixTimeSeconds()
    $Anchor = ($Anchors | Measure-Object -Maximum).Maximum
    return [pscustomobject]@{ active = ($Now - $Anchor) -lt $GraceSeconds; until = $Anchor + $GraceSeconds; anchor = $Anchor; reason = '开机 / 登录 / 唤醒' }
}

# 每类原因的危险程度与说明（保护记录里逐条显示）
$RiskInfo = @{
    egress        = @('高', '普通流量出口不在白名单：代理节点或模式变了，经此出口的连接（包括 Claude 网页里的请求）用的不是白名单 IP。')
    egress_claude = @('高', 'claude.ai 出口不在白名单：Claude 继续联网时对方看到的是非白名单 IP，账号有风控风险。')
    isolation     = @('高', 'Claude 隔离规则未覆盖当前清单：保持锁定并同步隔离后才可人工解除。')
    killswitch    = @('高', '断网保护规则不完整：代理一旦断开，流量可能直接用真实 IP 发出。')
    claude_path   = @('高', 'Claude 已更新，但 ClaudeGuard 保护的还是旧路径：新版 Claude 不在出口拦截范围内。')
    core          = @('中', 'FlClash 内核未运行：代理中断。断网保护会拦住直连，真实 IP 不会泄露，但保护链出现缺口。')
    tun           = @('中', 'TUN 虚拟网卡未连接：代理中断。断网保护会拦住直连，真实 IP 不会泄露，但保护链出现缺口。')
    guard_daemon  = @('中', 'ClaudeGuard 守护进程未运行：少了每 3 秒一次的出口检查，只剩 NetGuard 每 10 秒一次的检查。')
    guard_helper  = @('中', 'ClaudeGuard 网络助手失联：出口不对时，可能无法及时切断 Claude 的网络。')
    user          = @('低', '用户主动操作，不是异常。')
    error         = @('中', '检查过程出错，无法确认当前是否安全。')
}
$LevelOrder = @{ '低' = 1; '中' = 2; '高' = 3 }
# 把发现项（带 key）或纯文字转成 {code,text,level,why}
function Format-Reasons($Items) {
    return @($Items | Where-Object { $_ } | ForEach-Object {
        if ($_ -is [string]) { $Code = 'error'; $Text = $_ } else { $Code = [string]$_.key; $Text = [string]$_.text }
        $Info = $RiskInfo[$Code]; if (-not $Info) { $Info = $RiskInfo['error'] }
        [ordered]@{ code = $Code; text = $Text; level = $Info[0]; why = $Info[1] }
    })
}
function Add-Event([string]$Type, [string]$Summary, $Reasons = @(), $Detail = $null) {
    $Items = @(Format-Reasons $Reasons)
    $Severity = if ($Items.Count) { ($Items | Sort-Object { $LevelOrder[$_.level] } -Descending | Select-Object -First 1).level } else { '—' }
    $Line = [ordered]@{ ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); source = 'NetGuard'; type = $Type; severity = $Severity; summary = $Summary; reasons = $Items; detail = $Detail } | ConvertTo-Json -Compress -Depth 6
    Add-Content -LiteralPath $EventsFile -Encoding UTF8 -Value $Line
    # 只保留最近 2000 条
    $All = @(Get-Content -LiteralPath $EventsFile -Encoding UTF8)
    if ($All.Count -gt 2200) { $All | Select-Object -Last 2000 | Set-Content -LiteralPath $EventsFile -Encoding UTF8 }
}
function Read-Guard {
    $G = $null
    if (Test-Path -LiteralPath $GuardFile) { try { $G = Get-Content -LiteralPath $GuardFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {} }
    if (-not $G) { $G = [pscustomobject]@{} }
    foreach ($Default in @(@('enabled', $true), @('lockdown', $false), @('since', 0), @('reasons', @()), @('bad_streak', 0), @('last_check', 0), @('last_findings', @()), @('triggers', 0), @('sync_error', $null), @('grace_until', 0), @('grace_noted', 0))) {
        if (-not ($G.PSObject.Properties.Name -contains $Default[0])) { $G | Add-Member -NotePropertyName $Default[0] -NotePropertyValue $Default[1] }
    }
    return $G
}
# 状态文件可能同时被 SYSTEM 循环和用户操作写，用全局互斥量串行化
function New-StateMutex([string]$Name='Global\NetGuardState') {
    # Both SYSTEM watch and an elevated manual command must open the same object.
    # The default creator DACL can deny the other principal during overlapping checks.
    $Security = New-Object Security.AccessControl.MutexSecurity
    $Security.SetAccessRuleProtection($true, $false)
    foreach ($Id in @('S-1-5-18', 'S-1-5-32-544')) {
        $Sid = New-Object Security.Principal.SecurityIdentifier($Id)
        $Rule = New-Object Security.AccessControl.MutexAccessRule($Sid, [Security.AccessControl.MutexRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)
        $Security.AddAccessRule($Rule)
    }
    $Created = $false
    return [Threading.Mutex]::new($false, $Name, [ref]$Created, $Security)
}
function Invoke-Locked([scriptblock]$Body) {
    $M = New-StateMutex
    $Got = $false
    try { $Got = $M.WaitOne(30000); if (-not $Got) { throw '等待状态锁超时' }; & $Body }
    finally { if ($Got) { $M.ReleaseMutex() }; $M.Dispose() }
}
function Get-ClaudeGuardHelper {
    foreach ($F in Get-ChildItem -Path (Join-Path $env:ProgramData 'ClaudeGuardNetwork') -Filter status.json -Recurse -ErrorAction SilentlyContinue) {
        try { return Get-Content -LiteralPath $F.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
    }
    return $null
}
# 返回当前所有“泄露风险”异常：@{key; text}。黄色提醒类（健康任务时间、版本待更新、严格路由证据）不在此列。
function Get-GuardFindings($State, [switch]$RequireConfirmedExit) {
    $F = @()
    $Wl = @($Config.whitelist)
    if ($RequireConfirmedExit -and $Wl.Count -eq 0) { $F += [pscustomobject]@{ key='egress'; text='白名单为空，无法验证安全解除' } }
    $Ip = Egress $Config.check_url
    if ($RequireConfirmedExit -and -not $Ip) { $F += [pscustomobject]@{ key='egress'; text='普通出口未取得，保持锁定' } }
    if ($Ip -and $Wl.Count -and $Ip -notin $Wl) { $F += [pscustomobject]@{ key = 'egress'; text = "普通出口 $Ip 不在白名单" } }
    $Cip = Egress $Config.claude_check_url
    if ($RequireConfirmedExit -and -not $Cip) { $F += [pscustomobject]@{ key='egress_claude'; text='claude.ai 出口未取得，保持锁定' } }
    if ($Cip -and $Wl.Count -and $Cip -notin $Wl) { $F += [pscustomobject]@{ key = 'egress_claude'; text = "claude.ai 出口 $Cip 不在白名单" } }
    if (-not (Get-Process -Name FlClashCore -ErrorAction SilentlyContinue)) { $F += [pscustomobject]@{ key = 'core'; text = 'FlClash 内核未运行' } }
    $Tun = Get-NetAdapter -Name FlClash -ErrorAction SilentlyContinue
    if (-not $Tun -or $Tun.Status -ne 'Up') { $F += [pscustomobject]@{ key = 'tun'; text = 'TUN 虚拟网卡未连接' } }
    if ($State.killswitch) {
        # 读取失败 ≠ 规则缺失：读不到时不算异常（状态页会单独显示读取错误），避免一次读取失败就误杀 Claude
        $Names = @(); $ReadOk = $false
        try { $W = [NetGuardWfp]::new(); try { $Names = @($W.CurrentByLayer()); $ReadOk = $true } finally { $W.Dispose() } } catch {}
        if ($ReadOk) {
            $Health = Get-RuleHealth $Names $State
            if (-not $Health.killswitch_complete) { $F += [pscustomobject]@{ key = 'killswitch'; text = '基础断网保护规则不完整' } }
            if ($State.claude_block -and -not $Health.claude_block_complete) { $F += [pscustomobject]@{ key = 'isolation'; text = 'Claude 隔离规则未覆盖当前程序清单' } }
        }
    }
    $Daemon = @(Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*ClaudeGuard*main.py*daemon*' })
    if (-not $Daemon.Count) { $F += [pscustomobject]@{ key = 'guard_daemon'; text = 'ClaudeGuard 守护进程未运行' } }
    $H = Get-ClaudeGuardHelper
    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    if (-not $H -or -not $H.ready -or ($Now - [double]$H.updated_at) -gt 30) { $F += [pscustomobject]@{ key = 'guard_helper'; text = 'ClaudeGuard 网络助手未就绪或状态过期' } }
    $Pkg = try { Get-CurrentClaudePackage } catch { $null }
    if (-not $Pkg -and $RequireConfirmedExit) { $F += [pscustomobject]@{ key='claude_path'; text='无法核实已安装的 Claude 桌面版，保持锁定' } }
    if ($Pkg) {
        $Expected = (Join-Path $Pkg.InstallLocation 'app\claude.exe').ToLowerInvariant()
        if ($Expected -notin @(Claude-Programs | ForEach-Object { $_.ToLowerInvariant() })) { $F += [pscustomobject]@{ key = 'claude_path'; text = "Claude 已更新到 $($Pkg.Version)，ClaudeGuard 保护的仍是旧路径" } }
    }
    return @($F)
}
# Claude 程序清单 + Store 当前版本目录下的 exe，都结束掉
function Stop-ClaudeProcesses {
    $Targets = @(Claude-Programs | ForEach-Object { $_.ToLowerInvariant() })
    $Pkg = try { Get-CurrentClaudePackage } catch { $null }
    $AppDir = if ($Pkg) { (Join-Path $Pkg.InstallLocation 'app').ToLowerInvariant() } else { $null }
    $Killed = 0
    foreach ($P in Get-Process -ErrorAction SilentlyContinue) {
        $Path = try { $P.Path } catch { $null }
        if (-not $Path) { continue }
        $L = $Path.ToLowerInvariant()
        if ($L -in $Targets -or ($AppDir -and $L.StartsWith($AppDir + '\'))) {
            try { Stop-Process -Id $P.Id -Force -ErrorAction Stop; $Killed++ } catch {}
        }
    }
    return $Killed
}
function Invoke-GuardTick {
    Invoke-Locked {
        $State = Read-State
        $G = Read-Guard
        $SyncFailure = $null
        if ($G.lockdown -and $G.enabled) {
            try { Sync-LockedIsolation $State $G | Out-Null; $G.sync_error = $null }
            catch {
                $SyncFailure = $_.Exception.Message
                if ($G.sync_error -ne $SyncFailure) {
                    Add-Event 'isolation_sync_failed' '隔离同步未完成，保持锁定' @([pscustomobject]@{ key='isolation'; text=$SyncFailure })
                }
                $G.sync_error = $SyncFailure
            }
        }
        $Findings = @(Get-GuardFindings $State)
        if ($SyncFailure) { $Findings += [pscustomobject]@{ key='isolation'; text=$SyncFailure } }
        $G.last_check = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $G.last_findings = @($Findings | ForEach-Object { $_.text })
        $Grace = Get-GraceInfo
        $G | Add-Member -NotePropertyName grace_until -NotePropertyValue $(if ($Grace.active) { $Grace.until } else { 0 }) -Force
        if (-not $G.enabled) { $G.bad_streak = 0; Write-Json $GuardFile $G; return }
        if ($G.lockdown) { Write-Json $GuardFile $G; return }   # 已锁定，等待手动解除
        if ($Grace.active) {
            # 只放过明确登记为「中 / 低」的异常；未登记的类型一律照常计数（宁可多锁，不可漏锁）
            $Deferred = @($Findings | Where-Object { $Info = $RiskInfo[[string]$_.key]; $Info -and $Info[0] -ne '高' })
            if ($Deferred.Count -and [double]$G.grace_noted -ne [double]$Grace.anchor) {
                $Left = [int]($Grace.until - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
                Add-Event 'grace' "宽限期内（$($Grace.reason)，还剩约 $Left 秒）：中危异常暂不锁定，高危异常照常锁定" $Deferred
                $G | Add-Member -NotePropertyName grace_noted -NotePropertyValue $Grace.anchor -Force
            }
            $Findings = @($Findings | Where-Object { $_ -notin $Deferred })
        }
        if ($Findings.Count -eq 0) {
            if ($G.bad_streak -gt 0) { Add-Event 'recovered' '异常在确认前已恢复，未触发保护' @() }
            $G.bad_streak = 0; Write-Json $GuardFile $G; return
        }
        $G.bad_streak = [int]$G.bad_streak + 1
        if ($G.bad_streak -eq 1) { Add-Event 'suspect' "发现异常，等待确认（$GuardConfirm 次）" $Findings }
        if ($G.bad_streak -ge $GuardConfirm) {
            # 真实 IP 模式下 Claude 已被隔离：记录但不重复动作
            if ($State.claude_block) {
                if ($G.bad_streak -eq $GuardConfirm) { Add-Event 'info' 'Claude 已处于隔离（真实 IP 模式），不重复动作' $Findings }
                Write-Json $GuardFile $G; return
            }
            $G.lockdown = $true; $G.since = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $G.reasons = $G.last_findings; $G.triggers = [int]$G.triggers + 1
            $Err = $null
            try { $State.claude_block = $true; Apply $State; Write-Json $StateFile $State } catch { $Err = $_.Exception.Message }
            $Killed = Stop-ClaudeProcesses
            $Summary = if ($Err) { "已触发保护，但 WFP 隔离失败：$Err；已结束 $Killed 个 Claude 进程" } else { "已触发保护：Claude 已断网隔离，结束 $Killed 个 Claude 进程" }
            Add-Event 'trigger' $Summary $Findings ([ordered]@{ isolated = (-not $Err); killed = $Killed; error = $Err })
            Log $Summary
        }
        Write-Json $GuardFile $G
    }
}

function Write-Status {
    $State = Read-State
    [string[]]$Names = @()
    $Err = $null
    try { $W = [NetGuardWfp]::new(); try { $Names = @($W.CurrentByLayer()) } finally { $W.Dispose() } } catch { $Err = $_.Exception.Message }
    $Health = Get-RuleHealth $Names $State
    $Strict = Get-StrictRouteRuntime
    $G = Read-Guard
    Write-Json $StatusFile ([ordered]@{
        strict_route_runtime = $Strict
        guard = [ordered]@{ enabled = [bool]$G.enabled; lockdown = [bool]$G.lockdown; since = $G.since; reasons = @($G.reasons)
                            bad_streak = $G.bad_streak; confirm = $GuardConfirm; interval = $GuardInterval; last_check = $G.last_check
                            last_findings = @($G.last_findings); triggers = $G.triggers; grace_until = $G.grace_until }
        base_filter_count=$Health.base_filter_count; expected_base_filter_count=$Health.expected_base_filter_count
        required_claude_filter_count=$Health.required_claude_filter_count; covered_claude_filter_count=$Health.covered_claude_filter_count
        extra_claude_filter_count=$Health.extra_claude_filter_count
        status_version = 3; updated_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        wanted_killswitch = [bool]$State.killswitch; active_killswitch = [bool]($Health.active_killswitch -and -not $Err)
        wanted_claude_block = [bool]$State.claude_block; active_claude_block = [bool]($Health.active_claude_block -and -not $Err)
        killswitch_complete = [bool]($Health.killswitch_complete -and -not $Err)
        claude_block_complete = [bool]($Health.claude_block_complete -and -not $Err)
        integrity_ok = [bool]($Health.integrity_ok -and -not $Err)
        expected_filter_count = $Health.expected_filter_count; filter_count = $Names.Count; error = $Err })
}

try {
    $State = Read-State
    switch ($Action) {
        'enable' {
            $Before = Egress $Config.check_url
            if (-not $Before) { throw '当前无法通过代理联网（FlClash/TUN 未就绪？），拒绝开启，以免整机断网。' }
            if ($Config.whitelist -and $Before -notin @($Config.whitelist)) { throw "当前出口 $Before 不在白名单，请先让 FlClash 回到正常节点再开启。" }
            $PreviousState = $State.PSObject.Copy()
            $State.killswitch = $true
            Apply $State
            Start-Sleep -Seconds 2
            $After = Egress $Config.check_url
            if (-not $After -or ($Config.whitelist -and $After -notin @($Config.whitelist))) {
                Apply $PreviousState
                $State = $PreviousState
                throw '开启后自检未通过，已恢复操作前的保护状态；没有撤掉原本已开启的保护。'
            }
            Write-Json $StateFile $State
            Add-Event 'config' "断网保护已开启（出口 $After）" @([pscustomobject]@{ key = 'user'; text = '用户开启断网保护' })
            Log "已开启，出口 $After"
            Write-Host "全局断网保护已开启，出口 $After"
        }
        'disable' {
            Invoke-Locked {
                $S = Read-State; $S.killswitch = $false; $S.claude_block = $false
                Apply $S; Write-Json $StateFile $S
                $G = Read-Guard
                if ($G.lockdown) { $G.lockdown = $false; $G.bad_streak = 0; Write-Json $GuardFile $G; Add-Event 'release' '关闭断网保护时一并解除了自动防护锁定（用户操作，未做检查）' @() }
            }
            Add-Event 'config' '断网保护已关闭（代理断开时可能经真实 IP 联网）' @([pscustomobject]@{ key = 'user'; text = '用户关闭断网保护' })
            Log '已关闭'; Write-Host '全局断网保护已关闭，Claude 封锁已解除。'
        }
        'release' {
            Invoke-Locked {
                $S = Read-State; $G = Read-Guard
                if (-not $G.lockdown) { $script:NothingToRelease = $true; return }
                Sync-LockedIsolation $S $G | Out-Null
                $Findings = @(Get-GuardFindings $S -RequireConfirmedExit)
                if ($Findings.Count) {
                    $Texts = @($Findings | ForEach-Object { $_.text })
                    Add-Event 'release_refused' '解除被拒绝：检查仍未通过，保持锁定' $Findings
                    throw ('仍有异常，保持锁定：' + ($Texts -join '；'))
                }
                # Probes take time: revalidate both protected identities before lifting isolation.
                Get-RequiredClaudePrograms | Out-Null
                $S.claude_block = $false; Apply $S; Write-Json $StateFile $S
                $G.lockdown = $false; $G.bad_streak = 0; $G.reasons = @(); $G.sync_error = $null; Write-Json $GuardFile $G
                Add-Event 'release' '检查全部通过，已解除锁定，Claude 可以重新打开' @()
            }
            if ($script:NothingToRelease) { Write-Host '当前没有自动防护锁定。' } else { Log '已解除自动防护锁定'; Write-Host '已解除锁定，Claude 可以重新打开。' }
        }
        'guard-on' { Invoke-Locked { $G = Read-Guard; $G.enabled = $true; $G.bad_streak = 0; Write-Json $GuardFile $G; Add-Event 'config' '自动防护已开启' @() }; Log '自动防护已开启' }
        'guard-off' { Invoke-Locked { $G = Read-Guard; $G.enabled = $false; $G.bad_streak = 0; Write-Json $GuardFile $G; Add-Event 'config' '自动防护已关闭（不影响断网保护规则和现有锁定）' @() }; Log '自动防护已关闭' }
        'watch' {
            # 常驻循环：每 $GuardInterval 秒检查一次，不主动退出（v1.3.2）。
            # 旧做法“每分钟启动、跑 55 秒退出”因启动耗时超过 60 秒，每隔一分钟就漏掉一次启动，出现约 1 分钟的检查断档。
            # 计划任务的“每分钟触发 + IgnoreNew”现在只充当看门狗：循环在跑时触发被忽略，循环意外退出时 1 分钟内重新拉起。
            $PrevTick = $null
            while ($true) {
                $TickStart = Get-Date
                # 两次检查之间实际间隔远超节拍，说明系统刚从睡眠 / 休眠唤醒：重新开始宽限期
                if ($PrevTick -and ($TickStart - $PrevTick).TotalSeconds -gt 60) { $script:ResumeAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
                $PrevTick = $TickStart
                try { Invoke-GuardTick } catch { Log ('自动防护检查出错：' + $_.Exception.Message); try { Add-Event 'guard_error' ('自动防护检查出错：' + $_.Exception.Message) @([pscustomobject]@{ key = 'error'; text = $_.Exception.Message }) } catch {} }
                try { Write-Status } catch { Log ('写状态出错：' + $_.Exception.Message) }
                # 按固定节拍睡眠：扣掉本轮检查耗时，保持约 10 秒一次
                $Left = $GuardInterval - ((Get-Date) - $TickStart).TotalSeconds
                if ($Left -gt 0) { Start-Sleep -Milliseconds ([int]($Left * 1000)) }
            }
        }
        'claude-block' {
            $State.claude_block = $true
            Apply $State; Write-Json $StateFile $State
            Add-Event 'isolate' '已隔离 Claude（用户进入真实 IP 模式）' @([pscustomobject]@{ key = 'user'; text = '用户进入真实 IP 模式' })
            Log '已封锁 Claude（真实 IP 模式）'; Write-Host 'Claude 程序已被强制断网。'
        }
        'claude-unblock' {
            if ((Read-Guard).lockdown) { throw '当前处于自动防护锁定，请在工作台用「解除锁定」（会先完整检查）。' }
            $Ip = Egress $Config.check_url
            $ClaudeIp = Egress $Config.claude_check_url
            if (-not $Config.whitelist -or $Ip -notin @($Config.whitelist) -or $ClaudeIp -notin @($Config.whitelist)) {
                throw "出口尚未回到白名单（普通出口 $Ip，Claude 看到 $ClaudeIp），保持封锁。请先把 FlClash 切回正常模式。"
            }
            $State.claude_block = $false
            Apply $State; Write-Json $StateFile $State
            Add-Event 'unisolate' "已解除 Claude 隔离（用户退出真实 IP 模式，出口 $Ip 已核实在白名单）" @([pscustomobject]@{ key = 'user'; text = '用户退出真实 IP 模式' })
            Log "已解除 Claude 封锁，出口 $Ip"; Write-Host "已解除 Claude 封锁，出口 $Ip"
        }
        'status' { }
    }
} catch {
    Log ('错误：' + $_.Exception.Message)
    Write-Status
    Write-Host ('失败：' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
Write-Status
exit 0
