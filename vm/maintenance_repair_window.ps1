param(
    [string]$VmName = "KICBA-Lab",
    [string]$IsolatedSwitch = "KICBA-Isolated",
    [string]$OnlineSwitch = "Default Switch",
    [string]$AdapterName = "Maintenance-Online",
    [string]$AdapterMac = "00155D77AA01",
    [string]$GuestIPv4 = "192.168.77.2",
    [string]$StatusPath = "D:\KICBA-Lab\maintenance_network_status.json"
)

$ErrorActionPreference = "Stop"
$doneFlag = Join-Path $PSScriptRoot "maintenance_done.flag"
$adapterAdded = $false

function Write-Status([hashtable]$Values) {
    $temporary = $StatusPath + ".tmp"
    $Values.UpdatedUtc = [DateTime]::UtcNow.ToString("o")
    $Values | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $StatusPath -Force
}

try {
    Import-Module Hyper-V
    if (Test-Path -LiteralPath $doneFlag) {
        throw "Stale maintenance completion flag exists: $doneFlag"
    }
    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Running") {
        throw "VM must be running on the isolated network before maintenance"
    }
    $primary = @(Get-VMNetworkAdapter -VMName $VmName | Where-Object {
        $_.SwitchName -eq $IsolatedSwitch
    })
    if ($primary.Count -ne 1) {
        throw "Expected exactly one adapter on $IsolatedSwitch"
    }
    $maintenance = Get-VMNetworkAdapter -VMName $VmName -Name $AdapterName `
        -ErrorAction SilentlyContinue
    if (-not $maintenance) {
        Add-VMNetworkAdapter -VMName $VmName -Name $AdapterName `
            -SwitchName $OnlineSwitch -StaticMacAddress $AdapterMac
        $adapterAdded = $true
    } elseif ($maintenance.SwitchName -ne $OnlineSwitch) {
        throw "Existing maintenance adapter is connected to an unexpected switch"
    }

    Write-Status @{
        Stage = "maintenance_online"
        AdapterName = $AdapterName
        AdapterMac = $AdapterMac
        WaitingFor = $doneFlag
    }
    $deadline = (Get-Date).AddMinutes(30)
    do {
        Start-Sleep -Seconds 5
    } until ((Test-Path -LiteralPath $doneFlag) -or (Get-Date) -ge $deadline)
    if (-not (Test-Path -LiteralPath $doneFlag)) {
        throw "Maintenance completion flag was not created within 30 minutes"
    }

    Write-Status @{ Stage = "removing_maintenance_adapter" }
    $maintenance = Get-VMNetworkAdapter -VMName $VmName -Name $AdapterName `
        -ErrorAction SilentlyContinue
    if ($maintenance) {
        Remove-VMNetworkAdapter -VMNetworkAdapter $maintenance
        $adapterAdded = $false
    }

    $vm = Get-VM -Name $VmName
    if ($vm.State -eq "Running") {
        Stop-VM -Name $VmName -Force
        $deadline = (Get-Date).AddMinutes(3)
        do {
            Start-Sleep -Seconds 5
            $vm = Get-VM -Name $VmName
        } until ($vm.State -eq "Off" -or (Get-Date) -ge $deadline)
    }
    if ($vm.State -ne "Off") {
        throw "VM did not reach the Off state after maintenance"
    }

    Set-VMFirmware -VMName $VmName -EnableSecureBoot Off
    Set-VM -Name $VmName -CheckpointType Standard
    $snapshotName = "Clean-Repaired-Isolated-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Write-Status @{ Stage = "checkpointing"; SnapshotName = $snapshotName }
    Checkpoint-VM -Name $VmName -SnapshotName $snapshotName
    Start-VM -Name $VmName | Out-Null

    Write-Status @{ Stage = "waiting_for_isolated_ssh"; SnapshotName = $snapshotName }
    $deadline = (Get-Date).AddMinutes(5)
    $sshReady = $false
    do {
        Start-Sleep -Seconds 5
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $async = $client.BeginConnect($GuestIPv4, 22, $null, $null)
            $sshReady = $async.AsyncWaitHandle.WaitOne(1000) -and $client.Connected
        } finally {
            $client.Close()
        }
    } until ($sshReady -or (Get-Date) -ge $deadline)
    if (-not $sshReady) {
        throw "Repaired VM did not reopen isolated SSH at $GuestIPv4"
    }

    Write-Status @{
        Stage = "ready"
        SnapshotName = $snapshotName
        GuestIPv4 = $GuestIPv4
        MaintenanceAdapterPresent = $false
        SecureBoot = "Off"
        InternetRouteExpected = $false
    }
} catch {
    if ($adapterAdded) {
        try {
            $maintenance = Get-VMNetworkAdapter -VMName $VmName -Name $AdapterName `
                -ErrorAction SilentlyContinue
            if ($maintenance) {
                Remove-VMNetworkAdapter -VMNetworkAdapter $maintenance
            }
        } catch {}
    }
    Write-Status @{
        Stage = "failed"
        Error = $_.Exception.Message
        ScriptStackTrace = $_.ScriptStackTrace
    }
    exit 1
}
