param(
    [string]$VmName = "KICBA-Lab",
    [string]$IsoPath = "D:\KICBA-Lab\iso\ubuntu-22.04.5-kicba-autoinstall-amd64.iso",
    [string]$StatusPath = "D:\KICBA-Lab\autoinstall_status.json"
)

$ErrorActionPreference = "Stop"

function Write-Status([hashtable]$Values) {
    $temporary = $StatusPath + ".tmp"
    $Values.UpdatedUtc = [DateTime]::UtcNow.ToString("o")
    $Values | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $StatusPath -Force
}

try {
    if (-not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
        throw "Autoinstall ISO not found: $IsoPath"
    }
    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -eq "Running") {
        Write-Status @{ Stage = "stopping_preinstall_boot"; VmState = "Running" }
        Stop-VM -Name $VmName -TurnOff -Force
    } elseif ($vm.State -ne "Off") {
        throw "VM is in unexpected preinstall state: $($vm.State)"
    }

    $dvd = Get-VMDvdDrive -VMName $VmName | Select-Object -First 1
    if (-not $dvd) {
        throw "VM has no DVD drive"
    }
    Set-VMDvdDrive -VMName $VmName -ControllerNumber $dvd.ControllerNumber `
        -ControllerLocation $dvd.ControllerLocation -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $VmName | Select-Object -First 1
    Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd

    $installStarted = [DateTime]::UtcNow
    Start-VM -Name $VmName | Out-Null
    Write-Status @{
        Stage = "installing"
        VmState = "Running"
        IsoPath = $IsoPath
        InstallStartedUtc = $installStarted.ToString("o")
    }

    $installDeadline = $installStarted.AddMinutes(45)
    do {
        Start-Sleep -Seconds 10
        $vm = Get-VM -Name $VmName
        $elapsed = ([DateTime]::UtcNow - $installStarted).TotalSeconds
        $heartbeat = Get-VMIntegrationService -VMName $VmName -Name Heartbeat `
            -ErrorAction SilentlyContinue
        Write-Status @{
            Stage = "installing"
            VmState = $vm.State.ToString()
            ElapsedSeconds = [math]::Round($elapsed, 1)
            Heartbeat = if ($heartbeat) { $heartbeat.PrimaryStatusDescription } else { "Unavailable" }
            InstallStartedUtc = $installStarted.ToString("o")
        }
    } until ($vm.State -eq "Off" -or [DateTime]::UtcNow -ge $installDeadline)

    if ($vm.State -ne "Off") {
        throw "Autoinstall did not power off within 45 minutes"
    }
    if (([DateTime]::UtcNow - $installStarted).TotalMinutes -lt 3) {
        throw "VM powered off too quickly; treating autoinstall as failed"
    }

    $disk = Get-VMHardDiskDrive -VMName $VmName | Select-Object -First 1
    if (-not $disk) {
        throw "VM has no hard disk after installation"
    }
    Set-VMDvdDrive -VMName $VmName -ControllerNumber $dvd.ControllerNumber `
        -ControllerLocation $dvd.ControllerLocation -Path $null
    Set-VMFirmware -VMName $VmName -FirstBootDevice $disk
    Start-VM -Name $VmName | Out-Null

    $bootStarted = [DateTime]::UtcNow
    $bootDeadline = $bootStarted.AddMinutes(10)
    $ipv4 = @()
    do {
        Start-Sleep -Seconds 10
        $vm = Get-VM -Name $VmName
        $adapter = Get-VMNetworkAdapter -VMName $VmName
        $ipv4 = @($adapter.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
        Write-Status @{
            Stage = "first_boot"
            VmState = $vm.State.ToString()
            IPv4 = $ipv4
            BootElapsedSeconds = [math]::Round(([DateTime]::UtcNow - $bootStarted).TotalSeconds, 1)
        }
    } until ($ipv4.Count -gt 0 -or [DateTime]::UtcNow -ge $bootDeadline)

    Write-Status @{
        Stage = if ($ipv4.Count -gt 0) { "ready" } else { "running_without_reported_ip" }
        VmState = $vm.State.ToString()
        IPv4 = $ipv4
        CompletedUtc = [DateTime]::UtcNow.ToString("o")
    }
} catch {
    Write-Status @{
        Stage = "failed"
        Error = $_.Exception.Message
        ScriptStackTrace = $_.ScriptStackTrace
    }
    exit 1
}
