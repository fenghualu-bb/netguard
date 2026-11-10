param([string]$Source=(Join-Path $PSScriptRoot '..\admin\netguard.ps1'))
$ErrorActionPreference='Stop';$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Source),[ref]$t,[ref]$e)
if($e.Count){throw $e[0]}
$selector=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CurrentClaudePackage'},$true)
Invoke-Expression $selector.Extent.Text
$required=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-RequiredClaudePrograms'},$true)
$finding=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-GuardFindings'},$true)
Invoke-Expression $finding.Extent.Text
$script:Fail=0;$script:Passed=0
function Expect([bool]$OK,[string]$Name){if($OK){$script:Passed++;Write-Output "PASS $Name"}else{$script:Fail++;Write-Output "FAIL $Name"}}
function Required-Case([string[]]$Programs,[string[]]$Anchors,[string]$Cli='C:\CLI\claude.exe',[string]$Missing='',[string]$Desktop='C:\Store\Current\app\claude.exe'){
    $ManifestJson=([pscustomobject]@{programs=$Programs;paths=$Anchors;request='C:\Fixture\data\network-request.json'}|ConvertTo-Json -Depth 4)
    $ConfigJson=([pscustomobject]@{desktop_path=$Desktop;cli_path=$Cli}|ConvertTo-Json)
    function Get-ChildItem{[CmdletBinding()]param($Path,$Filter,[switch]$Recurse);[pscustomobject]@{FullName='manifest.json'}}
    function Get-Content{[CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding);if($LiteralPath -eq 'manifest.json'){$ManifestJson}else{$ConfigJson}}
    function Test-Path{param($LiteralPath,$PathType);$LiteralPath -ne $Missing}
    function Get-AppxPackage{[CmdletBinding()]param([switch]$AllUsers,$Name);[pscustomobject]@{InstallLocation='C:\Store\Current';PackageUserInformation=@([pscustomobject]@{InstallState='Installed'})}}
    try{$paths=@(& $required.Body.GetScriptBlock());return [pscustomobject]@{accepted=$true;count=$paths.Count}}catch{return [pscustomobject]@{accepted=$false;count=0}}
}
$desktop='C:\Store\Current\app\claude.exe';$cli='C:\CLI\claude.exe';$old='C:\Store\Previous\app\claude.exe'
Expect ((Required-Case @($desktop,$cli) @($desktop,$cli)).accepted) 'validator accepts exact current Desktop and configured CLI'
Expect (-not (Required-Case @($desktop,$old) @($desktop,$cli)).accepted) 'two Desktop executables cannot substitute for the configured CLI'
Expect (-not (Required-Case @($desktop,$cli) @($desktop,$cli) -Cli 'C:\NewCLI\claude.exe').accepted) 'changed configured CLI requires a matching refreshed manifest'
Expect (-not (Required-Case @($desktop,$cli) @($desktop,$cli) -Missing $cli).accepted) 'missing configured CLI file prevents repair'
Expect (-not (Required-Case @($desktop,$old,$cli) @($old,$cli) -Desktop $old).accepted) 'old Desktop configuration is rejected even if program scan includes the new Desktop'
Expect (-not (Required-Case @($desktop,$cli) @($desktop,$cli) -Cli $desktop).accepted) 'Desktop cannot be configured as the CLI identity'

# Real findings function with only OS/network boundaries replaced. No real probes or WFP calls.
$Config=[pscustomobject]@{whitelist=@('203.0.113.10');check_url='ordinary';claude_check_url='claude'}
$script:Exit=@{ordinary=$null;claude=$null}
function Egress($Url){$script:Exit[$Url]}
function Get-Process{param($Name,$ErrorAction);[pscustomobject]@{Id=1}}
function Get-NetAdapter{param($Name,$ErrorAction);[pscustomobject]@{Status='Up'}}
function Get-CimInstance{param($ClassName,$Filter,$ErrorAction);[pscustomobject]@{CommandLine='ClaudeGuard main.py daemon'}}
function Get-ClaudeGuardHelper{[pscustomobject]@{ready=$true;updated_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}}
function Get-AppxPackage{param([switch]$AllUsers,$Name,$ErrorAction);[pscustomobject]@{InstallLocation='C:\Store\Current';Version='1';PackageUserInformation=@([pscustomobject]@{InstallState='Installed'})}}
function Claude-Programs{@($desktop,$cli)}
$state=[pscustomobject]@{killswitch=$false;claude_block=$false}
Expect (@(Get-GuardFindings $state).Count -eq 0) 'watch keeps the existing non-killing policy for an unavailable exit probe'
Expect (@(Get-GuardFindings $state -RequireConfirmedExit).Count -gt 0) 'manual release refuses when both exit probes are unavailable'
$script:Exit.ordinary='203.0.113.10'
Expect (@(Get-GuardFindings $state -RequireConfirmedExit).Count -gt 0) 'manual release refuses when only one domain exit is verified'
$script:Exit.claude='203.0.113.10'
Expect (@(Get-GuardFindings $state -RequireConfirmedExit).Count -eq 0) 'manual release accepts two verified whitelist exits'
$Config.whitelist=@()
Expect (@(Get-GuardFindings $state -RequireConfirmedExit).Count -gt 0) 'manual release refuses an empty whitelist'
if($script:Fail){throw ('FAILED '+$script:Fail+' release/target validation checks')}
Write-Output ('PASSED '+$script:Passed+' release/target checks')
