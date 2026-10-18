param(
    [Parameter(Mandatory = $true)]
    [string]$GatewayUrl,

    [string]$TokenFile = "C:\ProgramData\DefensaAzul\gateway-token.txt",

    [string]$RunId = "defended-live",
    [string]$TargetId = $env:COMPUTERNAME.ToLowerInvariant(),
    [string]$StatePath = "C:\ProgramData\DefensaAzul\windows-agent-state.json",
    [int]$PollSeconds = 10,
    [int]$BootstrapLookbackMinutes = 30,
    [int]$MaxWindowsEventsPerLoop = 50,
    [string[]]$AllowedBlockSources = @(),
    [string[]]$ProtectedSources = @("127.0.0.1"),
    [string]$BridgeSource = "",
    [string]$BridgeTarget = "win-dc01",
    [switch]$EnableBlocking,
    [switch]$Once
)

$ErrorActionPreference = "Stop"

if ($EnableBlocking) {
    throw "Windows blocking is disabled until independent rollback recovery is implemented and tested."
}
$Token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($Token)) { throw "Endpoint token file is empty" }

$logDir = Split-Path -Parent $StatePath
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Start-Transcript -Path (Join-Path $logDir "windows-agent.log") -Append | Out-Null

$interestingEvents = @{
    "Security" = @(4624, 4625, 4672, 4688, 4697, 4720, 4722, 4728, 4732, 4738, 4740, 4771, 4776, 5140, 5145)
    "System" = @(7036, 7045)
    "Microsoft-Windows-Sysmon/Operational" = @(1, 3, 7, 10, 11, 22)
}

$severityByEventId = @{
    "4624" = "info"
    "4625" = "medium"
    "4672" = "high"
    "4688" = "low"
    "4697" = "high"
    "4720" = "high"
    "4722" = "medium"
    "4728" = "critical"
    "4732" = "high"
    "4738" = "medium"
    "4740" = "medium"
    "4771" = "medium"
    "4776" = "medium"
    "5140" = "low"
    "5145" = "medium"
    "7036" = "info"
    "7045" = "high"
    "1" = "medium"
    "3" = "medium"
    "7" = "low"
    "10" = "high"
    "11" = "low"
    "22" = "medium"
}

function Get-UtcIso {
    return [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
}

function New-StableId {
    param([string]$Prefix, [string]$Material)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Material)
    $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    return "$Prefix-$($hash.Substring(0, 32))"
}

function Read-State {
    if (Test-Path -LiteralPath $StatePath) {
        $raw = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        $state = @{}
        foreach ($property in $raw.PSObject.Properties) {
            $state[$property.Name] = $property.Value
        }
        return $state
    }
    return @{}
}

function Write-State {
    param([hashtable]$State)
    $dir = Split-Path -Parent $StatePath
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Convert-EventData {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $data = @{}
    try {
        [xml]$xml = $Event.ToXml()
        $xml.Event.EventData.Data | ForEach-Object {
            $name = $_.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "Data$($data.Count)"
            }
            $data[$name] = $_."#text"
        }
        $xml.Event.UserData.ChildNodes | ForEach-Object {
            foreach ($child in $_.ChildNodes) {
                $data[$child.Name] = $child.InnerText
            }
        }
    } catch {
        $data["message"] = $Event.FormatDescription()
    }
    return $data
}

function Send-DefensaEvent {
    param([hashtable]$Event)
    $json = $Event | ConvertTo-Json -Depth 10 -Compress
    $body = [System.Text.Encoding]::UTF8.GetBytes($json)
    Invoke-RestMethod `
        -Method Post `
        -Uri "$($GatewayUrl.TrimEnd('/'))/v1/events" `
        -Headers @{ Authorization = "Bearer $Token" } `
        -ContentType "application/json; charset=utf-8" `
        -Body $body | Out-Null
}

function Get-DefensaEvents {
    try {
        $response = Invoke-RestMethod `
            -Method Get `
            -Uri "$($GatewayUrl.TrimEnd('/'))/v1/actions?run_id=$RunId&target_id=$TargetId&action_type=windows_firewall_block" `
            -Headers @{ Authorization = "Bearer $Token" }
        return @($response.events)
    } catch {
        Write-Warning "Failed to poll Defensa action queue: $($_.Exception.Message)"
        return @()
    }
}

function Send-Heartbeat {
    $now = Get-UtcIso
    $eventId = New-StableId "evt" "$RunId|$TargetId|heartbeat|$now"
    Send-DefensaEvent @{
        schema_version = "1.0.0"
        event_id = $eventId
        event_type = "defense.endpoint.heartbeat"
        time = $now
        observed_time = $now
        run_id = $RunId
        target_id = $TargetId
        actor = @{ type = "agent"; id = "defensa-windows-agent@$TargetId" }
        severity = "info"
        confidence = 1.0
        evidence_ids = @()
        payload = @{
            hostname = $env:COMPUTERNAME
            user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            os = (Get-CimInstance Win32_OperatingSystem).Caption
            mode = if ($EnableBlocking) { "enforce" } else { "observe" }
            blocking_enabled = [bool]$EnableBlocking
        }
    }
}

function Get-NewEvents {
    param([hashtable]$State)
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($logName in $interestingEvents.Keys) {
        try {
            Get-WinEvent -ListLog $logName -ErrorAction Stop | Out-Null
        } catch {
            continue
        }

        $lastRecordId = 0
        if ($State.ContainsKey($logName)) {
            $lastRecordId = [int64]$State[$logName]
        }

        $filter = @{ LogName = $logName; Id = $interestingEvents[$logName] }
        if ($lastRecordId -eq 0) {
            $filter.StartTime = (Get-Date).AddMinutes(-1 * $BootstrapLookbackMinutes)
        }

        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction SilentlyContinue) |
                Where-Object { $_.RecordId -gt $lastRecordId } |
                Sort-Object RecordId
            foreach ($event in $events) {
                $all.Add($event)
                if ($event.RecordId -gt $lastRecordId) {
                    $lastRecordId = $event.RecordId
                }
            }
            $State[$logName] = $lastRecordId
        } catch [System.Exception] {
            if ($_.Exception.Message -notmatch "No events were found") {
                Write-Warning "Failed to read ${logName}: $($_.Exception.Message)"
            }
        }
    }
    return $all
}

function Send-WindowsEvents {
    param([object[]]$Events)
    foreach ($event in $Events) {
        $observed = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        $eventId = New-StableId "evt" "$RunId|$TargetId|$($event.ProviderName)|$($event.RecordId)"
        $evidenceId = New-StableId "evidence" "$RunId|$TargetId|$($event.ProviderName)|$($event.RecordId)"
        $eventData = Convert-EventData $event
        $severity = $severityByEventId[[string]$event.Id]
        if (-not $severity) {
            $severity = "info"
        }
        Send-DefensaEvent @{
            schema_version = "1.0.0"
            event_id = $eventId
            event_type = "defense.endpoint.windows_event"
            time = Get-UtcIso
            observed_time = $observed
            run_id = $RunId
            target_id = $TargetId
            actor = @{ type = "agent"; id = "defensa-windows-agent@$TargetId" }
            severity = $severity
            confidence = 0.86
            evidence_ids = @($evidenceId)
            payload = @{
                hostname = $env:COMPUTERNAME
                channel = $event.LogName
                provider = $event.ProviderName
                event_id = $event.Id
                record_id = $event.RecordId
                level = $event.LevelDisplayName
                task = $event.TaskDisplayName
                event_data = $eventData
                mode = if ($EnableBlocking) { "enforce" } else { "observe" }
                blocking_enabled = [bool]$EnableBlocking
            }
        }
    }
}

function Get-EventIds {
    param($Proposal, $Decision)
    $ids = New-Object System.Collections.Generic.List[string]
    if ($Decision.event_id) {
        $ids.Add([string]$Decision.event_id)
    }
    foreach ($id in @($Proposal.payload.evidence_ids)) {
        if ($id) {
            $ids.Add([string]$id)
        }
    }
    return @($ids)
}

function Send-ActionResult {
    param($Proposal, $Decision, [string]$Status, [hashtable]$Result)
    $proposalId = [string]$Proposal.payload.proposal_id
    Send-DefensaEvent @{
        schema_version = "1.0.0"
        event_id = New-StableId "evt-action" "$RunId|$TargetId|$proposalId"
        event_type = "defense.action.result"
        time = Get-UtcIso
        observed_time = Get-UtcIso
        run_id = $RunId
        target_id = $TargetId
        incident_id = [string]$Proposal.payload.incident_id
        actor = @{ type = "agent"; id = "defensa-windows-agent@$TargetId" }
        severity = "high"
        confidence = [double]$Proposal.payload.confidence
        evidence_ids = @(Get-EventIds $Proposal $Decision)
        payload = @{
            proposal_id = $proposalId
            decision_event_id = [string]$Decision.event_id
            action_type = [string]$Proposal.payload.action_type
            status = $Status
            ttl_seconds = [int]$Proposal.payload.ttl_seconds
            result = $Result
        }
    }
}

function Send-Rollback {
    param([string]$ProposalId, [string]$IncidentId, [string]$ActionType, [hashtable]$Result)
    Send-DefensaEvent @{
        schema_version = "1.0.0"
        event_id = New-StableId "evt-rollback" "$RunId|$TargetId|$ProposalId"
        event_type = "defense.rollback"
        time = Get-UtcIso
        observed_time = Get-UtcIso
        run_id = $RunId
        target_id = $TargetId
        incident_id = $IncidentId
        actor = @{ type = "agent"; id = "defensa-windows-agent@$TargetId" }
        severity = "info"
        confidence = 1.0
        evidence_ids = @(New-StableId "evt-action" "$RunId|$TargetId|$ProposalId")
        payload = @{
            proposal_id = $ProposalId
            action_type = $ActionType
            status = $Result.status
            rollback = $Result
        }
    }
}

function Read-ActionResource {
    param($Proposal)
    try {
        return ([string]$Proposal.payload.resource | ConvertFrom-Json)
    } catch {
        throw "Action resource is not valid JSON: $($_.Exception.Message)"
    }
}

function Assert-WindowsFirewallResource {
    param($Resource)
    $srcIp = [string]$Resource.src_ip
    $protocol = ([string]$Resource.protocol).ToLowerInvariant()
    $direction = ([string]$Resource.direction).ToLowerInvariant()
    $dstPort = [int]$Resource.dst_port
    $ruleName = [string]$Resource.rule_name
    if ($AllowedBlockSources.Count -eq 0) {
        throw "Refusing firewall block because AllowedBlockSources is empty"
    }
    if ($AllowedBlockSources -notcontains $srcIp) {
        throw "Refusing to block non-allowlisted source IP $srcIp"
    }
    if ($ProtectedSources -contains $srcIp) {
        if (-not ($BridgeSource -and $srcIp -eq $BridgeSource -and $TargetId -eq $BridgeTarget -and $dstPort -eq 445)) {
            throw "Refusing to block protected infrastructure IP $srcIp"
        }
    }
    if ($protocol -ne "tcp") {
        throw "Refusing non-TCP firewall block $protocol"
    }
    if ($direction -ne "inbound") {
        throw "Refusing non-inbound firewall block $direction"
    }
    if (@(445, 3389, 5985) -notcontains $dstPort) {
        throw "Refusing non-allowlisted Windows destination port $dstPort"
    }
    if ($BridgeSource -and $srcIp -eq $BridgeSource -and (-not ($TargetId -eq $BridgeTarget -and $dstPort -eq 445))) {
        throw "Refusing bridge-source block except $BridgeTarget inbound SMB"
    }
    if (-not $ruleName.StartsWith("DefensaAzul block ")) {
        throw "Refusing firewall rule without DefensaAzul prefix"
    }
}

function Invoke-ApprovedActions {
    param([object[]]$Events, [hashtable]$State)
    if ($Events.Count -eq 0) {
        return
    }
    $proposals = @{}
    foreach ($event in $Events) {
        if ($event.event_type -eq "defense.proposal" -and $event.payload.proposal_id) {
            $proposals[[string]$event.payload.proposal_id] = $event
        }
    }
    foreach ($decision in $Events) {
        if ($decision.event_type -ne "defense.decision") {
            continue
        }
        if ($decision.target_id -ne $TargetId) {
            continue
        }
        if ($decision.payload.status -ne "allowed") {
            continue
        }
        $proposalId = [string]$decision.payload.proposal_id
        if (-not $proposalId -or $State.ContainsKey("action:$proposalId")) {
            continue
        }
        $proposal = $proposals[$proposalId]
        if (-not $proposal -or $proposal.payload.action_type -ne "windows_firewall_block") {
            continue
        }

        $status = "failed"
        $result = @{
            status = "failed"
            target_id = $TargetId
        }
        try {
            $resource = Read-ActionResource $proposal
            Assert-WindowsFirewallResource $resource
            $ruleName = [string]$resource.rule_name
            $dstPort = [int]$resource.dst_port
            $srcIp = [string]$resource.src_ip
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Direction Inbound `
                -Action Block `
                -Protocol TCP `
                -LocalPort $dstPort `
                -RemoteAddress $srcIp `
                -Profile Any | Out-Null
            $rollbackDue = [DateTime]::UtcNow.AddSeconds([int]$proposal.payload.ttl_seconds).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
            $status = "succeeded"
            $result = @{
                status = "succeeded"
                rule_name = $ruleName
                src_ip = $srcIp
                dst_port = $dstPort
                protocol = "tcp"
                direction = "inbound"
                rollback_due_utc = $rollbackDue
            }
            $State["rollback_due:$proposalId"] = $rollbackDue
            $State["rollback_rule:$proposalId"] = $ruleName
            $State["rollback_incident:$proposalId"] = [string]$proposal.payload.incident_id
            $State["rollback_action:$proposalId"] = [string]$proposal.payload.action_type
        } catch {
            $result = @{
                status = "failed"
                error = [string]$_.Exception.Message
                target_id = $TargetId
            }
        }
        Send-ActionResult $proposal $decision $status $result
        $State["action:$proposalId"] = $status
    }
}

function Invoke-PendingRollbacks {
    param([object[]]$Events, [hashtable]$State)
    $proposals = @{}
    foreach ($event in $Events) {
        if ($event.event_type -eq "defense.proposal" -and $event.payload.proposal_id) {
            $proposals[[string]$event.payload.proposal_id] = $event
        }
    }
    foreach ($key in @($State.Keys)) {
        if (-not ([string]$key).StartsWith("rollback_due:")) {
            continue
        }
        $proposalId = ([string]$key).Substring("rollback_due:".Length)
        if ($State.ContainsKey("rollback:$proposalId")) {
            continue
        }
        $due = [DateTime]::Parse([string]$State[$key]).ToUniversalTime()
        if ([DateTime]::UtcNow -lt $due) {
            continue
        }
        $ruleName = [string]$State["rollback_rule:$proposalId"]
        $status = "completed"
        $errorText = ""
        try {
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        } catch {
            $status = "failed"
            $errorText = [string]$_.Exception.Message
        }
        $proposal = $proposals[$proposalId]
        $incidentId = [string]$State["rollback_incident:$proposalId"]
        if (-not $incidentId -and $proposal) {
            $incidentId = [string]$proposal.payload.incident_id
        }
        $actionType = [string]$State["rollback_action:$proposalId"]
        if (-not $actionType -and $proposal) {
            $actionType = [string]$proposal.payload.action_type
        }
        if (-not $actionType) {
            $actionType = "windows_firewall_block"
        }
        Send-Rollback $proposalId $incidentId $actionType @{
            status = $status
            type = "remove_windows_firewall_rule"
            rule_name = $ruleName
            automatic = $true
            error = $errorText
        }
        $State["rollback:$proposalId"] = $status
    }
}

Write-Host "Starting Defensa Azul Windows agent for $TargetId -> $GatewayUrl"
Write-Host "Blocking enabled: $([bool]$EnableBlocking)"
Send-Heartbeat

do {
    $state = Read-State
    if ($EnableBlocking) {
        $defensaEvents = @(Get-DefensaEvents)
        Invoke-ApprovedActions $defensaEvents $state
        Invoke-PendingRollbacks $defensaEvents $state
        Write-State $state
    }
    $events = @(Get-NewEvents $state)
    if ($events.Count -gt $MaxWindowsEventsPerLoop) {
        Write-Host "Capping Windows event forwarding at $MaxWindowsEventsPerLoop of $($events.Count) events this loop"
        $events = @($events | Select-Object -First $MaxWindowsEventsPerLoop)
    }
    if ($events.Count -gt 0) {
        Send-WindowsEvents $events
    }
    Write-State $state
    if ($Once) {
        break
    }
    Start-Sleep -Seconds $PollSeconds
} while ($true)
