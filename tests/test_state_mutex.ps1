param([string]$Source=(Join-Path $PSScriptRoot '..\admin\netguard.ps1'))
$ErrorActionPreference='Stop';$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Source),[ref]$t,[ref]$e)
if($e.Count){throw $e[0]}
$TestName='Local\NetGuardOffline-'+[guid]::NewGuid().ToString('N')
# Rename only the kernel object for this test; never open the real Global mutex.
foreach($name in @('New-StateMutex','Invoke-Locked')){
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if($node){Invoke-Expression ($node.Extent.Text.Replace('Global\NetGuardState',$TestName))}
}
$script:AclRules=@()
Invoke-Locked {
 $Opened=[Threading.Mutex]::OpenExisting($TestName,[Security.AccessControl.MutexRights]::ReadPermissions)
 try{$script:AclRules=@($Opened.GetAccessControl().GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))}finally{$Opened.Dispose()}
}
$script:Fail=0;$script:Pass=0
function Expect([bool]$OK,$Text){if($OK){$script:Pass++;Write-Output ('PASS '+$Text)}else{$script:Fail++;Write-Output ('FAIL '+$Text)}}
foreach($sid in @('S-1-5-18','S-1-5-32-544')){
 $rule=@($script:AclRules|Where-Object{$_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow'})
 Expect ($rule.Count -eq 1 -and ($rule[0].MutexRights -band [Security.AccessControl.MutexRights]::FullControl) -eq [Security.AccessControl.MutexRights]::FullControl) ('state mutex explicitly grants FullControl to '+$sid)
}
Expect (@($script:AclRules|Where-Object{$_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')}).Count -eq 0) 'ordinary users and Everyone are not granted state-mutex access'
$caught=$false
try{Invoke-Locked {throw 'injected body failure'}}catch{$caught=$_.Exception.Message -eq 'injected body failure'}
$opened=$null;$left=[Threading.Mutex]::TryOpenExisting($TestName,[ref]$opened)
if($opened){$opened.Dispose()}
Expect ($caught -and -not $left) 'body exceptions propagate and the test mutex handle is disposed'
if($script:Fail){throw ('FAILED '+$script:Fail+' state mutex checks')}
Write-Output ('PASSED '+$script:Pass+' state mutex checks')
