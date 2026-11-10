param([string]$Source=(Join-Path $PSScriptRoot '..\admin\netguard.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Source),[ref]$tokens,[ref]$errors)
if($errors.Count){throw $errors[0]}
foreach($name in @('Get-RuleHealth','Sync-LockedIsolation','Invoke-GuardTick')){
    $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if($node){Invoke-Expression $node.Extent.Text}
}
# Replace only the native WFP boundary. No real engine is opened and no process is stopped.
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;
public class NetGuardWfp:IDisposable{
 public static List<string> Rules=new List<string>();public static bool FailAdd;public static int Added;
 public string[] CurrentByLayer(){return Rules.ToArray();}
 public int EnsureBlockedApps(string[] apps){
  if(FailAdd)throw new Exception("injected transaction failure");
  int count=0;foreach(string tag in new[]{"v4","v6"})foreach(string app in apps){
   string value=tag+"|NetGuard real-ip block "+app;if(!Rules.Contains(value)){Rules.Add(value);count++;}
  }Added+=count;return count;
 }
 public void Dispose(){}
}
'@
$base=@('v4|NetGuard permit TUN v4','v4|NetGuard permit proxy app C:\Proxy\FlClashCore.exe','v4|NetGuard permit proxy app C:\Proxy\FlClash.exe','v4|NetGuard block DNS outside TUN v4','v4|NetGuard permit loopback v4','v4|NetGuard permit LAN/link-local v4','v4|NetGuard block all other v4','v6|NetGuard permit TUN v6','v6|NetGuard permit proxy app C:\Proxy\FlClashCore.exe','v6|NetGuard permit proxy app C:\Proxy\FlClash.exe','v6|NetGuard block DNS outside TUN v6','v6|NetGuard permit loopback v6','v6|NetGuard permit LAN/link-local v6','v6|NetGuard block all other v6')
$script:Apps=@('C:\Claude\desktop.exe','C:\Claude\github-mcp.exe','C:\Claude\chrome-host.exe','C:\Claude\make-folder.exe','C:\Claude\askpass.exe','C:\Claude\ssh-broker.exe','C:\Claude\ssh-proxy.exe','C:\Claude\cowork.exe','C:\CLI\claude.exe')
$partial=@($base+'v4|NetGuard real-ip block C:\CLI\claude.exe'+'v6|NetGuard real-ip block C:\CLI\claude.exe')
$StateFile='state-fixture';$GuardFile='guard-fixture';$script:FailValidation=$false
function Proxy-Apps{@('C:\Proxy\FlClashCore.exe','C:\Proxy\FlClash.exe')}
function Claude-Programs{@($script:Apps)}
function Get-RequiredClaudePrograms{if($script:FailValidation){throw 'stale manifest'};@($script:Apps)}
function Add-Event($Type,$Summary,$Reasons=@(),$Detail=$null){$script:Events+=@($Type)}
function Write-Json($Path,$Value){if($Path -eq $StateFile){$script:State=$Value}else{$script:Guard=$Value}}
function Read-State{$script:State}
function Read-Guard{$script:Guard}
function Invoke-Locked([scriptblock]$Body){&$Body}
function Log($Text){}
function Reset-Case([string[]]$Names){
 [NetGuardWfp]::Rules=[Collections.Generic.List[string]]::new();[NetGuardWfp]::Rules.AddRange($Names)
 [NetGuardWfp]::FailAdd=$false;[NetGuardWfp]::Added=0
 $script:State=[pscustomobject]@{killswitch=$true;claude_block=$true}
 $script:Guard=[pscustomobject]@{enabled=$true;lockdown=$true;bad_streak=2;reasons=@('path changed');sync_error=$null;last_check=0;last_findings=@();triggers=1}
 $script:Events=@();$script:FailValidation=$false
}
$script:Failures=@();$script:Passed=0
function Expect([bool]$OK,[string]$Name){if($OK){$script:Passed++;Write-Output "PASS $Name"}else{$script:Failures+=@($Name);Write-Output "FAIL $Name"}}
function Get-GuardFindings($Value){$r=Get-RuleHealth ([NetGuardWfp]::Rules.ToArray()) $Value;if(-not $r.integrity_ok){[pscustomobject]@{key='isolation';text='incomplete'}}}
Reset-Case $partial
$h=Get-RuleHealth ([NetGuardWfp]::Rules.ToArray()) $script:State
Expect ($h.killswitch_complete -and -not $h.claude_block_complete -and -not $h.integrity_ok) 'partial Claude isolation does not invalidate the complete base killswitch'
Expect ($h.base_filter_count -eq 14 -and $h.covered_claude_filter_count -eq 2 -and $h.required_claude_filter_count -eq 18) 'partial status reports independent base and isolation counts'
if(Get-Command Sync-LockedIsolation -ErrorAction SilentlyContinue){
 $changed=Sync-LockedIsolation $script:State $script:Guard
 $h=Get-RuleHealth ([NetGuardWfp]::Rules.ToArray()) $script:State
 Expect ($changed -and $h.integrity_ok -and [NetGuardWfp]::Rules.Count -eq 32 -and [NetGuardWfp]::Added -eq 16) 'locked manifest growth from one to nine programs adds the missing sixteen deny rules'
 Expect ($script:Guard.lockdown -and $script:State.claude_block -and $script:Events -contains 'isolation_sync') 'automatic reconciliation records repair and never releases the lock'
 $again=Sync-LockedIsolation $script:State $script:Guard
 Expect (-not $again -and [NetGuardWfp]::Added -eq 16) 'reconciliation is idempotent after successful repair'
 $existing=[NetGuardWfp]::Rules.ToArray();[NetGuardWfp]::Rules.Add('v4|NetGuard real-ip block C:\Old\claude.exe');[NetGuardWfp]::Rules.Add('v6|NetGuard real-ip block C:\Old\claude.exe')
 $h=Get-RuleHealth ([NetGuardWfp]::Rules.ToArray()) $script:State
 Expect ($h.integrity_ok -and $h.extra_claude_filter_count -eq 2 -and $h.expected_filter_count -eq 34) 'older additional deny rules are retained without a false integrity failure'
 Reset-Case $partial;[NetGuardWfp]::FailAdd=$true;$caught=$false
 try{Sync-LockedIsolation $script:State $script:Guard|Out-Null}catch{$caught=$true}
 Expect ($caught -and $script:Guard.lockdown -and [NetGuardWfp]::Rules.Count -eq 16) 'failed reconciliation leaves existing deny rules and lock intact'
 Reset-Case @($partial|Where-Object{$_ -ne 'v6|NetGuard block all other v6'});$caught=$false
 try{Sync-LockedIsolation $script:State $script:Guard|Out-Null}catch{$caught=$true}
 Expect ($caught -and [NetGuardWfp]::Added -eq 0 -and $script:Guard.lockdown) 'missing base protection is refused rather than silently rebuilt or released'
 Reset-Case $partial;$script:FailValidation=$true;$caught=$false
 try{Sync-LockedIsolation $script:State $script:Guard|Out-Null}catch{$caught=$true}
 Expect ($caught -and [NetGuardWfp]::Added -eq 0 -and $script:Guard.lockdown) 'obsolete program manifest prevents a claimed repair'
 Reset-Case $partial
 Invoke-GuardTick
 Expect ($script:Guard.lockdown -and $script:State.claude_block -and [NetGuardWfp]::Rules.Count -eq 32 -and $script:Guard.last_findings.Count -eq 0 -and $script:Guard.last_check -gt 0) 'real watch tick repairs isolation and persists a fresh locked status'
 Reset-Case $partial;[NetGuardWfp]::FailAdd=$true
 Invoke-GuardTick
 Invoke-GuardTick
 Expect ($script:Guard.lockdown -and [NetGuardWfp]::Rules.Count -eq 16 -and $script:Guard.sync_error -and @($script:Events|Where-Object{$_ -eq 'isolation_sync_failed'}).Count -eq 1) 'watch tick retains lock on repair failure and avoids duplicate failure events'
 # Execute the actual manual-release branch; the boundary below models only applying a cleared isolation state.
 Reset-Case $partial
 function Apply($Value){if(-not $Value.claude_block){[NetGuardWfp]::Rules.Clear();[NetGuardWfp]::Rules.AddRange([string[]]$base)}}
 $switch=$ast.Find({param($n)$n -is [Management.Automation.Language.SwitchStatementAst]},$true)
 $Action='release';$script:NothingToRelease=$false;$caught=$false
 try{Invoke-Expression $switch.Extent.Text}catch{$caught=$true}
 Expect (-not $caught -and -not $script:Guard.lockdown -and -not $script:State.claude_block -and [NetGuardWfp]::Rules.Count -eq 14) 'explicit manual release repairs the changed manifest then validates before lifting isolation'
}else{Expect $false 'locked manifest reconciliation is implemented'}
if($script:Failures.Count){throw ('FAILED '+$script:Failures.Count+' isolation-sync regression checks')}
Write-Output ('PASSED '+$script:Passed+' isolation-sync checks')
