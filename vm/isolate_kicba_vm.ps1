param(
    [string]$VmName = "KICBA-Lab",
    [string]$SwitchName = "KICBA-Isolated",
    [string]$HostIPv4 = "192.168.77.1",
    [string]$GuestIPv4 = "192.168.77.2",
    [int]$PrefixLength = 24,
    [string]$StatusPath = "D:\KICBA-Lab\isolation_status.json"
)

$ErrorActionPreference = "Stop"

function Write-Status([hashtable]$Values) {
    $temporary = $StatusPath + ".tmp"
    $Values.UpdatedUtc = [DateTime]::UtcNow.ToString("o")
    $Values | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $StatusPath -Force
}

try {
    Import-Module Hyper-V
    $vm = Get-VM -Name $VmName -ErrorAction Stop

    if ($vm.State -eq "Running") {
        Write-Status @{ Stage = "shutting_down"; VmState = "Running" }
        # Stop-VM performs a guest shutdown by default; -Force suppresses the
        # interactive confirmation if the integration service cannot respond.
        # -TurnOff is deliberately not used because it is an abrupt power cut.
        Stop-VM -Name $VmName -Force
        $deadline = (Get-Date).AddMinutes(3)
        do {
            Start-Sleep -Seconds 5
            $vm = Get-VM -Name $VmName
        } until ($vm.State -eq "Off" -or (Get-Date) -ge $deadline)
        if ($vm.State -ne "Off") {
            throw "Guest did not shut down cleanly within three minutes"
        }
    } elseif ($vm.State -ne "Off") {
        throw "VM is in unexpected state: $($vm.State)"
    }

    # The pinned CARAXES module is intentionally unsigned.  Disable Secure Boot
    # only for this disposable, host-only research VM so Ubuntu does not enter
    # integrity lockdown and reject the module.  This does not change host
    # Secure Boot or Windows security settings.
    Set-VMFirmware -VMName $VmName -EnableSecureBoot Off
    $firmware = Get-VMFirmware -VMName $VmName
    if ($firmware.SecureBoot -ne "Off") {
        throw "Failed to disable Secure Boot for the isolated research VM"
    }

    Set-VM -Name $VmName -CheckpointType Standard
    $snapshotName = "Clean-Isolated-SecureBootOff-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Write-Status @{
        Stage = "checkpointing"
        SnapshotName = $snapshotName
        SecureBoot = "Off"
    }
    Checkpoint-VM -Name $VmName -SnapshotName $snapshotName

    $switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        $switch = New-VMSwitch -Name $SwitchName -SwitchType Internal
    } elseif ($switch.SwitchType -ne "Internal") {
        throw "Existing switch '$SwitchName' is not an Internal switch"
    }

    $interfaceAlias = "vEthernet ($SwitchName)"
    $existingIPv4 = @(Get-NetIPAddress -InterfaceAlias $interfaceAlias `
        -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    $correctIPv4 = @($existingIPv4 | Where-Object {
        $_.IPAddress -eq $HostIPv4 -and $_.PrefixLength -eq $PrefixLength
    })
    if ($existingIPv4.Count -gt 0 -and $correctIPv4.Count -eq 0) {
        throw "Internal switch already has an unexpected IPv4 configuration"
    }
    if ($correctIPv4.Count -eq 0) {
        New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $HostIPv4 `
            -PrefixLength $PrefixLength | Out-Null
    }

    Connect-VMNetworkAdapter -VMName $VmName -SwitchName $SwitchName
    Start-VM -Name $VmName | Out-Null
    Write-Status @{
        Stage = "waiting_for_isolated_ssh"
        SnapshotName = $snapshotName
        SwitchName = $SwitchName
        HostIPv4 = $HostIPv4
        GuestIPv4 = $GuestIPv4
        SecureBoot = "Off"
    }

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
        throw "VM started on the internal switch but SSH did not open at $GuestIPv4"
    }
    Write-Status @{
        Stage = "ready"
        VmState = "Running"
        SnapshotName = $snapshotName
        SwitchName = $SwitchName
        HostIPv4 = $HostIPv4
        GuestIPv4 = $GuestIPv4
        InternetRouteExpected = $false
        SecureBoot = "Off"
    }
} catch {
    Write-Status @{
        Stage = "failed"
        Error = $_.Exception.Message
        ScriptStackTrace = $_.ScriptStackTrace
    }
    exit 1
}
