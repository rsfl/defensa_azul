param(
    [Parameter(Mandatory = $true)]
    [string]$GatewayUrl,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$RunId = "defended-live",
    [string]$TargetId = $env:COMPUTERNAME.ToLowerInvariant(),
    [string]$InstallDir = "C:\ProgramData\DefensaAzul",
    [int]$PollSeconds = 10,
    [string[]]$AllowedBlockSources = @(),
    [string[]]$ProtectedSources = @("127.0.0.1"),
    [string]$BridgeSource = "",
    [string]$BridgeTarget = "win-dc01",
    [switch]$EnableBlocking
)

$ErrorActionPreference = "Stop"

$sourceAgent = Join-Path $PSScriptRoot "defensa-windows-agent.ps1"
$targetAgent = Join-Path $InstallDir "defensa-windows-agent.ps1"
$logPath = Join-Path $InstallDir "windows-agent.log"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
if ((Resolve-Path -LiteralPath $sourceAgent).Path -ne (Resolve-Path -LiteralPath $targetAgent -ErrorAction SilentlyContinue).Path) {
    Copy-Item -LiteralPath $sourceAgent -Destination $targetAgent -Force
}

$encodedArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$targetAgent`"",
    "-GatewayUrl", "`"$GatewayUrl`"",
    "-Token", "`"$Token`"",
    "-RunId", "`"$RunId`"",
    "-TargetId", "`"$TargetId`"",
    "-PollSeconds", "$PollSeconds"
) -join " "

if ($EnableBlocking) {
    $encodedArgs = "$encodedArgs -EnableBlocking"
}
if ($AllowedBlockSources.Count -gt 0) {
    $encodedArgs = "$encodedArgs -AllowedBlockSources $($AllowedBlockSources -join ',')"
}
if ($ProtectedSources.Count -gt 0) {
    $encodedArgs = "$encodedArgs -ProtectedSources $($ProtectedSources -join ',')"
}
if ($BridgeSource) {
    $encodedArgs = "$encodedArgs -BridgeSource `"$BridgeSource`""
}
if ($BridgeTarget) {
    $encodedArgs = "$encodedArgs -BridgeTarget `"$BridgeTarget`""
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $encodedArgs
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Days 365) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName "DefensaAzulWindowsAgent" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

Start-ScheduledTask -TaskName "DefensaAzulWindowsAgent"
Write-Host "Defensa Azul Windows agent installed and started for $TargetId"
Write-Host "Blocking enabled: $([bool]$EnableBlocking)"
Write-Host "Log: $logPath"
