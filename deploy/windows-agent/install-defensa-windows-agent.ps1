param(
    [Parameter(Mandatory = $true)]
    [string]$GatewayUrl,

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
if ($EnableBlocking) {
    throw "Windows blocking is disabled until independent rollback recovery is implemented and tested."
}

$sourceAgent = Join-Path $PSScriptRoot "defensa-windows-agent.ps1"
$targetAgent = Join-Path $InstallDir "defensa-windows-agent.ps1"
$logPath = Join-Path $InstallDir "windows-agent.log"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$dirAcl = New-Object System.Security.AccessControl.DirectorySecurity
$dirAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $dirAcl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $InstallDir -AclObject $dirAcl
$tokenFile = Join-Path $InstallDir "gateway-token.txt"
if (-not (Test-Path -LiteralPath $tokenFile)) { New-Item -ItemType File -Path $tokenFile | Out-Null }
$fileAcl = New-Object System.Security.AccessControl.FileSecurity
$fileAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
    $fileAcl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $tokenFile -AclObject $fileAcl
$secureToken = Read-Host "Endpoint token (input hidden)" -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($plainToken)) { throw "Endpoint token cannot be empty" }
    [IO.File]::WriteAllText($tokenFile, $plainToken, [Text.Encoding]::UTF8)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $plainToken = $null
    $secureToken.Dispose()
}
if ((Resolve-Path -LiteralPath $sourceAgent).Path -ne (Resolve-Path -LiteralPath $targetAgent -ErrorAction SilentlyContinue).Path) {
    Copy-Item -LiteralPath $sourceAgent -Destination $targetAgent -Force
}

$encodedArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$targetAgent`"",
    "-GatewayUrl", "`"$GatewayUrl`"",
    "-TokenFile", "`"$tokenFile`"",
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
