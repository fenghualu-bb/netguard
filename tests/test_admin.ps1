param([string]$Source = (Join-Path $PSScriptRoot '..\admin\netguard.ps1'))
$ErrorActionPreference = 'Stop'
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Source),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw $parseErrors[0]}
foreach($var in @('RiskInfo','LevelOrder')) {
    $assign=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$'+$var)},$true)
    Invoke-Expression $assign.Extent.Text
}
foreach($name in @('Write-Status','Get-RuleHealth','Get-StrictRouteRuntime','Read-Guard','Format-Reasons','Add-Event','Invoke-GuardTick')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if($node){Invoke-Expression $node.Extent.Text}
}
# Native WFP is intentionally replaced at the OS boundary: no engine or filter operation occurs.
Add-Type -TypeDefinition 'using System; public class NetGuardWfp:IDisposable { public static string[] Names, Tagged, External; public static bool ExternalThrows; public string[] Current(){return Names;} public string[] CurrentByLayer(){return Tagged;} public string[] ExternalMatching(string[] f){ if(ExternalThrows) throw new Exception("WFP 0x5"); return External ?? new string[0]; } public void Dispose(){} }'
$Config=[pscustomobject]@{allow_apps=@('C:\Proxy\FlClashCore.exe','C:\Proxy\FlClash.exe');whitelist=@('203.0.113.10');check_url='fixture';claude_check_url='fixture'}
$StatusFile='fixture'; $StateFile='fixture'; $GuardFile=Join-Path $env:TEMP ('ng-none-'+[guid]::NewGuid()+'.json'); $GuardConfirm=2; $GuardInterval=10
function Read-State { [pscustomobject]@{killswitch=$true;claude_block=$false} }
function Proxy-Apps { @('C:\Proxy\FlClashCore.exe','C:\Proxy\FlClash.exe') }
function Claude-Programs { @('C:\Claude\claude.exe') }
function Write-Json($Path,$Value){$script:Written=$Value}
function Log([string]$Text){}
# Reconciliation itself is exercised by test_isolation_sync.ps1 with the real implementation.
function Sync-LockedIsolation($State,$Guard){return $false}
function Get-RequiredClaudePrograms{return @('C:\Fixture\Desktop\claude.exe','C:\Fixture\CLI\claude.exe')}
# 宽限期替身：默认不在宽限期（旧测试行为不变）；$script:GraceActive=$true 模拟开机 / 唤醒后
$script:GraceActive=$false; $script:GraceAnchor=1000
function Get-GraceInfo { [pscustomobject]@{ active=$script:GraceActive; until=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+120; anchor=$script:GraceAnchor; reason='测试' } }
$full=@('NetGuard permit TUN v4','NetGuard permit proxy app C:\Proxy\FlClashCore.exe','NetGuard permit proxy app C:\Proxy\FlClash.exe','NetGuard block DNS outside TUN v4','NetGuard permit loopback v4','NetGuard permit LAN/link-local v4','NetGuard block all other v4','NetGuard permit TUN v6','NetGuard permit proxy app C:\Proxy\FlClashCore.exe','NetGuard permit proxy app C:\Proxy\FlClash.exe','NetGuard block DNS outside TUN v6','NetGuard permit loopback v6','NetGuard permit LAN/link-local v6','NetGuard block all other v6')
$failures=@()
$tagged=@('v4|NetGuard permit TUN v4','v4|NetGuard permit proxy app C:\Proxy\FlClashCore.exe','v4|NetGuard permit proxy app C:\Proxy\FlClash.exe','v4|NetGuard block DNS outside TUN v4','v4|NetGuard permit loopback v4','v4|NetGuard permit LAN/link-local v4','v4|NetGuard block all other v4','v6|NetGuard permit TUN v6','v6|NetGuard permit proxy app C:\Proxy\FlClashCore.exe','v6|NetGuard permit proxy app C:\Proxy\FlClash.exe','v6|NetGuard block DNS outside TUN v6','v6|NetGuard permit loopback v6','v6|NetGuard permit LAN/link-local v6','v6|NetGuard block all other v6')
function Expect([bool]$Passed,[string]$Name){if($Passed){Write-Output "PASS $Name"}else{$script:failures+=@($Name);Write-Output "FAIL $Name"}}
[NetGuardWfp]::Names=$full; [NetGuardWfp]::Tagged=$tagged; Write-Status
Expect ($Written.active_killswitch -eq $true) 'complete rules are active'
[NetGuardWfp]::Names=@($full|Where-Object{$_ -ne 'NetGuard block all other v6'}); [NetGuardWfp]::Tagged=@($tagged|Where-Object{$_ -ne 'v6|NetGuard block all other v6'}); Write-Status
Expect ($Written.active_killswitch -eq $false) 'missing IPv6 block is not active protection'
[NetGuardWfp]::Names=@($full|Where-Object{$_ -ne 'NetGuard permit TUN v6'}); [NetGuardWfp]::Tagged=@($tagged|Where-Object{$_ -ne 'v6|NetGuard permit TUN v6'}); Write-Status
Expect ($Written.active_killswitch -eq $false) 'missing TUN permit is reported incomplete'
[NetGuardWfp]::Names=@($full+'NetGuard unexpected rule'); [NetGuardWfp]::Tagged=@($tagged+'v4|NetGuard unexpected rule'); Write-Status
Expect ($Written.integrity_ok -eq $false) 'unexpected rules invalidate integrity'
[NetGuardWfp]::Names=$full; [NetGuardWfp]::Tagged=$tagged; Write-Status
Expect ($Written.integrity_ok -eq $true -and $Written.expected_filter_count -eq 14) 'complete rule schema reports verified count'
[NetGuardWfp]::Tagged=@($tagged | ForEach-Object { if($_ -eq 'v6|NetGuard permit proxy app C:\Proxy\FlClash.exe'){'v4|NetGuard permit proxy app C:\Proxy\FlClash.exe'}else{$_} }); Write-Status
Expect ($Written.active_killswitch -eq $false) 'duplicated IPv4 permit cannot substitute for missing IPv6 permit'

# strict-route runtime evidence (sing-tun filters in another sublayer)
$sing=@('L4|block|Meta|block ipv4 dns','L6|block|Meta|block ipv6','L6|block|Meta|block ipv6 dns','L4|permit|Meta|allow ipv4','L6|permit|Meta|allow ipv6 neighbor advertisement','L6|permit|Meta|allow ipv6 neighbor solicitation','L6|permit|Meta|allow ipv6 router solicitation','L4|permit|Meta|protect ipv4','L6|permit|Meta|protect ipv6')  # 2026-10-29 本机实测
[NetGuardWfp]::Names=$full; [NetGuardWfp]::Tagged=$tagged; [NetGuardWfp]::External=$sing; Write-Status
Expect ($Written.strict_route_runtime.detected -eq $true -and $Written.strict_route_runtime.dns_block -eq 2 -and $Written.strict_route_runtime.total -eq 9 -and $Written.strict_route_runtime.owner -eq 'Meta') 'real FlClash (owner Meta) strict-route filters are detected'
Expect ($Written.integrity_ok -eq $true -and $Written.active_killswitch -eq $true) 'strict-route probe does not disturb NetGuard integrity'
[NetGuardWfp]::External=@('L4|permit|sing-tun|allow ipv4','L6|permit|sing-tun|allow ipv6'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false) 'allow rules alone do not prove strict-route DNS blocking'
[NetGuardWfp]::External=@('L4|permit|sing-tun|block ipv4 dns'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false) 'a permit named like the DNS block is not proof'
[NetGuardWfp]::External=@('L4|block|Some IPv4 thing|'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false -and $Written.strict_route_runtime.names.Count -eq 1) 'unrelated names are sampled but not counted'
[NetGuardWfp]::External=@('L4|block|block ipv4 dns|'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false) 'rule text in NAME without sing-tun owner is not proof'
[NetGuardWfp]::External=@('L4|block|Other|block ipv4 dns'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false) 'another owner with the same description is not proof'
[NetGuardWfp]::External=@('L4|block|sing-tun|block ipv4 dns','L4|permit|sing-tun|protect ipv4'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $true -and $Written.strict_route_runtime.owner -eq 'sing-tun') 'owner name is not hard-coded (upstream sing-tun name also works)'
[NetGuardWfp]::External=@('L4|block|A|block ipv4 dns','L4|permit|B|protect ipv4'); Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false) 'DNS block and protect from different owners is not proof'
[NetGuardWfp]::ExternalThrows=$true; Write-Status
Expect ($Written.strict_route_runtime.detected -eq $false -and $Written.strict_route_runtime.error -and $Written.integrity_ok -eq $true) 'probe failure is reported without breaking integrity'
[NetGuardWfp]::ExternalThrows=$false; [NetGuardWfp]::External=@()

$switch=$ast.Find({param($n)$n -is [Management.Automation.Language.SwitchStatementAst]},$true)
$Action='enable'; $State=Read-State; $script:Applied=@();$script:Calls=0
function Apply($Value){$script:Applied+=@([bool]$Value.killswitch)}
function Egress([string]$Url){$script:Calls++;if($script:Calls -eq 1){return '203.0.113.10'};return $null}
function Start-Sleep{}
try {Invoke-Expression $switch.Extent.Text}catch{}
Expect ($Applied.Count -gt 0 -and $Applied[-1] -eq $true) 'failed re-enable preserves existing protection'
# ---------------- v1.3.0 自动防护（全部为替身，不碰 WFP、不结束任何进程）
$tmp = Join-Path $env:TEMP ('ngguard-' + [guid]::NewGuid()); New-Item -ItemType Directory $tmp | Out-Null
$GuardFile = "$tmp\guard.json"; $EventsFile = "$tmp\events.jsonl"; $StateFile = "$tmp\state.json"
function Write-Json($Path,$Value){ [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 6)); $script:Written = $Value }
function Read-State { if (Test-Path $StateFile) { Get-Content $StateFile -Raw | ConvertFrom-Json } else { [pscustomobject]@{ killswitch = $true; claude_block = $false } } }
function Invoke-Locked([scriptblock]$Body) { & $Body }
function Apply($S) { $script:ApplyLog += @([bool]$S.claude_block) }
function Stop-ClaudeProcesses { $script:Kills++; return 3 }
function Get-GuardFindings($S) { return @($script:Findings) }
function Events { if (Test-Path $EventsFile) { @(Get-Content $EventsFile -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json }) } else { @() } }
function Reset { Remove-Item "$tmp\*" -Force -ErrorAction SilentlyContinue; $script:ApplyLog = @(); $script:Kills = 0; $script:Findings = @() }
$bad = [pscustomobject]@{ key = 'egress'; text = '普通出口 1.2.3.4 不在白名单' }

Reset; Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $false -and (Read-Guard).bad_streak -eq 0 -and (Events).Count -eq 0) 'guard: healthy tick does nothing'
Reset; $script:Findings = @($bad); Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $false -and (Read-Guard).bad_streak -eq 1 -and $script:Kills -eq 0 -and (Events)[-1].type -eq 'suspect') 'guard: first failure only records suspect (debounce)'
Invoke-GuardTick
$g = Read-Guard; $ev = Events
Expect ($g.lockdown -eq $true -and $script:ApplyLog[-1] -eq $true -and $script:Kills -eq 1 -and $ev[-1].type -eq 'trigger' -and $ev[-1].detail.killed -eq 3 -and @($g.reasons)[0] -like '*1.2.3.4*') 'guard: second consecutive failure isolates Claude, kills processes, records trigger'
$tr=$ev[-1]
Expect ($tr.severity -eq '高' -and $tr.source -eq 'NetGuard' -and @($tr.reasons)[0].code -eq 'egress' -and @($tr.reasons)[0].level -eq '高' -and @($tr.reasons)[0].why -and @($tr.reasons)[0].text -like '*1.2.3.4*') 'records: trigger carries reason, level and explanation'
Invoke-GuardTick
Expect ($script:Kills -eq 1 -and (Events).Count -eq $ev.Count) 'guard: no repeated action while locked'
Reset; $script:Findings = @([pscustomobject]@{ key='tun'; text='TUN 虚拟网卡未连接' }); Invoke-GuardTick
Expect ((Events)[-1].severity -eq '中' -and @((Events)[-1].reasons)[0].level -eq '中') 'records: TUN down is medium severity'
Reset; $script:Findings = @([pscustomobject]@{ key='tun'; text='TUN 虚拟网卡未连接' }, $bad); Invoke-GuardTick
Expect ((Events)[-1].severity -eq '高' -and @((Events)[-1].reasons).Count -eq 2) 'records: overall severity is the highest reason'
Reset; $script:Findings = @($bad); Invoke-GuardTick; $script:Findings = @(); Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $false -and (Events)[-1].type -eq 'recovered' -and $script:Kills -eq 0) 'guard: transient failure recovers without trigger'
Reset; Write-Json $StateFile ([pscustomobject]@{ killswitch = $true; claude_block = $true }); $script:Findings = @($bad); Invoke-GuardTick; Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $false -and $script:Kills -eq 0 -and (Events)[-1].type -eq 'info') 'guard: real-IP mode (Claude already isolated) does not re-trigger'
Reset; Write-Json $GuardFile ([pscustomobject]@{ enabled = $false }); $script:Findings = @($bad); Invoke-GuardTick; Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $false -and $script:Kills -eq 0) 'guard: disabled guard never acts'
# release（取 switch 里的真实分支执行）
Reset; $script:Findings = @($bad); Invoke-GuardTick; Invoke-GuardTick
$Action = 'release'; $failedRelease = $false
try { Invoke-Expression $switch.Extent.Text } catch { $failedRelease = $true }
Expect ($failedRelease -and (Read-Guard).lockdown -eq $true -and (Events)[-1].type -eq 'release_refused') 'release: refused while findings remain, lock kept'
$script:Findings = @(); $script:NothingToRelease = $false
Invoke-Expression $switch.Extent.Text
Expect ((Read-Guard).lockdown -eq $false -and (Read-State).claude_block -eq $false -and $script:ApplyLog[-1] -eq $false -and (Events)[-1].type -eq 'release') 'release: clean checks unlock and lift isolation'
# ---------------- v1.3.5 开机 / 唤醒宽限期
$boot = @([pscustomobject]@{ key='core'; text='FlClash 内核未运行' }, [pscustomobject]@{ key='tun'; text='TUN 虚拟网卡未连接' }, [pscustomobject]@{ key='guard_daemon'; text='ClaudeGuard 守护进程未运行' })
Reset; $script:GraceActive=$true; $script:GraceAnchor=1000; $script:Findings=$boot
Invoke-GuardTick; Invoke-GuardTick; Invoke-GuardTick
$ev=@(Events)
Expect ((Read-Guard).lockdown -eq $false -and $script:Kills -eq 0 -and (Read-Guard).bad_streak -eq 0) 'grace: boot-time medium findings never lock (the 6 false lockdowns)'
Expect ($ev.Count -eq 1 -and $ev[0].type -eq 'grace' -and $ev[0].severity -eq '中' -and @($ev[0].reasons).Count -eq 3) 'grace: deferral recorded once per grace window with reasons'
Expect ((Read-Guard).grace_until -gt 0 -and @((Read-Guard).last_findings).Count -eq 3) 'grace: status still shows the current findings and grace end'
Reset; $script:GraceActive=$true; $script:Findings=@($boot + $bad); Invoke-GuardTick; Invoke-GuardTick
$tr=@(Events | Where-Object { $_.type -eq 'trigger' })
Expect ((Read-Guard).lockdown -eq $true -and $script:Kills -eq 1 -and $tr.Count -eq 1 -and @($tr[0].reasons).Count -eq 1 -and @($tr[0].reasons)[0].code -eq 'egress') 'grace: high-risk finding still locks inside grace (reasons = high only)'
Reset; $script:GraceActive=$true; $script:Findings=@([pscustomobject]@{ key='claude_path'; text='Claude 已更新到 9.9，ClaudeGuard 保护的仍是旧路径' }); Invoke-GuardTick; Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $true) 'grace: Claude path change still locks inside grace'
Reset; $script:GraceActive=$true; $script:Findings=@([pscustomobject]@{ key='unknown_new_check'; text='新类型异常' }); Invoke-GuardTick; Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $true) 'grace: unregistered finding types are not deferred (fail closed)'
Reset; $script:GraceActive=$true; $script:Findings=$boot; Invoke-GuardTick; $script:GraceActive=$false; Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $false -and (Read-Guard).bad_streak -eq 1 -and (Events)[-1].type -eq 'suspect') 'grace: after grace ends, still-missing proxy starts normal confirmation'
Invoke-GuardTick
Expect ((Read-Guard).lockdown -eq $true -and (Read-Guard).grace_until -eq 0) 'grace: proxy still down after grace -> locks as before'
Reset; $script:GraceActive=$true; $script:GraceAnchor=1000; $script:Findings=$boot; Invoke-GuardTick; $script:GraceAnchor=2000; Invoke-GuardTick
Expect (@(Events | Where-Object { $_.type -eq 'grace' }).Count -eq 2) 'grace: a new wake/logon window is recorded again'
$script:GraceActive=$false
$resolvedCleanup=(Resolve-Path -LiteralPath $tmp).ProviderPath
$allowedCleanupBase=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
if(-not $resolvedCleanup.StartsWith($allowedCleanupBase,[StringComparison]::OrdinalIgnoreCase)){throw 'Cleanup outside test temp directory'}
Remove-Item -LiteralPath $resolvedCleanup -Recurse -Force
# ---------------- v1.3.2 常驻 watch 循环（替身：不检查、不写文件；第 4 次睡眠时用异常结束测试）
$script:Sleeps=@(); $script:Ticks=0
function Invoke-GuardTick { $script:Ticks++; if ($script:Ticks -eq 2) { throw '模拟一次检查出错' } }
function Write-Status { }
function Start-Sleep([int]$Milliseconds,[int]$Seconds) { $script:Sleeps += $Milliseconds; if ($script:Sleeps.Count -ge 4) { throw 'STOP-LOOP' } }
function Add-Event { }
$Action='watch'; $stopped=$false
try { Invoke-Expression $switch.Extent.Text } catch { $stopped = $_.Exception.Message -eq 'STOP-LOOP' }
Expect ($stopped -and $script:Ticks -eq 4) 'watch: loop keeps running after a failed check (no exit)'
Expect (@($script:Sleeps | Where-Object { $_ -gt 9000 -and $_ -le 10000 }).Count -eq 4) 'watch: sleeps interval minus tick time (about 10 s cadence)'
if($failures.Count){throw ('Failed '+$failures.Count+' admin regression checks')}
