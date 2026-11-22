param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^DefensaAzul block [A-Za-z0-9 .:_-]+$')]
    [string]$RuleName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^DefensaAzulRollback-[a-f0-9]{24}$')]
    [string]$TaskName
)

$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
