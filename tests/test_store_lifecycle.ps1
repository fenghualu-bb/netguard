param([string]$Source=(Join-Path $PSScriptRoot '..\admin\netguard.ps1'))
$ErrorActionPreference='Stop'
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Source),[ref]$t,[ref]$e)
if($e.Count){throw $e[0]}
foreach($name in @('Get-CurrentClaudePackage','Get-RequiredClaudePrograms','Get-GuardFindings','Stop-ClaudeProcesses')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if($node){Invoke-Expression $node.Extent.Text}
}
# Real validation/findings/termination selectors; OS boundaries are fixtures only.
function Package($Version,$Folder,$State,$Status='Ok'){
 [pscustomobject]@{Version=[version]$Version;InstallLocation=$Folder;Status=$Status;PackageUserInformation=@([pscustomobject]@{InstallState=$State})}
}
$script:Old=Package '4.16336.0.0' 'C:\Store\Current' 'Installed'
$script:New=Package '4.23118.0.0' 'C:\Store\Pending' 'Staged' 'Servicing'
$script:Packages=@($script:Old,$script:New)
$desktop='C:\Store\Current\app\claude.exe';$cli='C:\CLI\claude.exe'
$script:Covered=@($desktop,$cli)
function Get-AppxPackage{[CmdletBinding()]param([switch]$AllUsers,$Name);@($script:Packages)}
function Get-ChildItem{[CmdletBinding()]param($Path,$Filter,[switch]$Recurse);[pscustomobject]@{FullName='manifest.json'}}
function Get-Content{[CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding);if($LiteralPath -eq 'manifest.json'){
 [pscustomobject]@{paths=@($desktop,$cli);programs=$script:Covered;request='C:\Fixture\data\network-request.json'}|ConvertTo-Json
 }else{[pscustomobject]@{desktop_path=$desktop;cli_path=$cli}|ConvertTo-Json}}
function Test-Path{param($LiteralPath,$PathType);$true}
function Claude-Programs{@($script:Covered)}
function Egress($Url){'203.0.113.10'}
function Get-NetAdapter{param($Name,$ErrorAction);[pscustomobject]@{Status='Up'}}
function Get-CimInstance{param($ClassName,$Filter,$ErrorAction);[pscustomobject]@{CommandLine='ClaudeGuard main.py daemon'}}
function Get-ClaudeGuardHelper{[pscustomobject]@{ready=$true;updated_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}}
function Get-Process{param($Name,$ErrorAction);if($Name){[pscustomobject]@{Id=1}}else{@([pscustomobject]@{Id=101;Path=$desktop},[pscustomobject]@{Id=102;Path='C:\Store\Current\app\child.exe'},[pscustomobject]@{Id=103;Path='C:\Other\safe.exe'})}}
function Stop-Process{param($Id,[switch]$Force,$ErrorAction);$script:Stopped+=@($Id)}
$Config=[pscustomobject]@{whitelist=@('203.0.113.10');check_url='ordinary';claude_check_url='claude'}
$state=[pscustomobject]@{killswitch=$false;claude_block=$false}
$script:Failed=0;$script:Passed=0
function Expect([bool]$OK,$Text){if($OK){$script:Passed++;Write-Output ('PASS '+$Text)}else{$script:Failed++;Write-Output ('FAIL '+$Text)}}
$accepted=$false;try{$paths=@(Get-RequiredClaudePrograms);$accepted=$paths.Count -eq 2}catch{}
Expect $accepted 'a newer Staged/Servicing package does not invalidate the installed Desktop manifest'
Expect (@(Get-GuardFindings $state).Count -eq 0) 'a staged-only update does not trigger automatic path protection'
Expect (@(Get-GuardFindings $state -RequireConfirmedExit).Count -eq 0) 'manual release remains possible for a verified installed version during staging'
$script:Stopped=@();$count=Stop-ClaudeProcesses
Expect ($count -eq 2 -and 102 -in $script:Stopped -and 103 -notin $script:Stopped) 'termination selector still includes children of the installed Desktop'
$script:New.PackageUserInformation[0].InstallState='Installed'
$accepted=$true;try{Get-RequiredClaudePrograms|Out-Null}catch{$accepted=$false}
Expect (-not $accepted) 'a genuinely installed newer Desktop still requires a refreshed protected manifest'
Expect (@(Get-GuardFindings $state|Where-Object{$_.key -eq 'claude_path'}).Count -eq 1) 'a genuinely installed newer Desktop still triggers path protection'
$script:Packages=@($script:New);$script:New.PackageUserInformation[0].InstallState='Staged'
$accepted=$true;try{Get-RequiredClaudePrograms|Out-Null}catch{$accepted=$false}
Expect (-not $accepted) 'staged-only inventory without an installed Desktop cannot pass target validation'
Expect (@(Get-GuardFindings $state -RequireConfirmedExit).Count -gt 0) 'manual release refuses when installed Desktop identity is unavailable'
if($script:Failed){throw ('FAILED '+$script:Failed+' Store lifecycle checks')}
Write-Output ('PASSED '+$script:Passed+' Store lifecycle checks')
