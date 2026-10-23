#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$vmName = 'KICBA-Lab'
$snapshotName = 'Before-Phase2-Applicability-Cost-20261023'
$evidenceDirectory = Join-Path $PSScriptRoot 'evidence'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
$reportPath = Join-Path $evidenceDirectory 'checkpoint.json'
try {
    $targetVm = Get-VM -Name $vmName -ErrorAction Stop
    if (@($targetVm).Count -ne 1) { throw 'Expected exactly one original lab VM.' }
    $before = @(Get-VMSnapshot -VM $targetVm)
    $existing = @($before | Where-Object { $_.Name -eq $snapshotName })
    if ($existing.Count -gt 1) { throw 'Ambiguous checkpoint name.' }
    if ($existing.Count -eq 0) {
        $created = Checkpoint-VM -VM $targetVm -SnapshotName $snapshotName -Passthru -ErrorAction Stop
        $action = 'created'
    } else {
        $created = $existing[0]
        $action = 'verified_existing'
    }
    $verified = Get-VMSnapshot -VM $targetVm | Where-Object { $_.Id -eq $created.Id }
    if ($null -eq $verified) { throw 'Checkpoint could not be verified after creation.' }
    $record = [ordered]@{
        success = $true
        action = $action
        recorded_at = (Get-Date).ToString('o')
        vm_name = $targetVm.Name
        vm_id = $targetVm.Id.ToString()
        vm_state = $targetVm.State.ToString()
        vm_version = $targetVm.Version
        checkpoint_type_setting = $targetVm.CheckpointType.ToString()
        checkpoint_name = $verified.Name
        checkpoint_id = $verified.Id.ToString()
        checkpoint_creation_time = $verified.CreationTime.ToString('o')
        previous_checkpoints = @($before | Select-Object Name,Id,CreationTime)
        disks = @(Get-VMHardDiskDrive -VM $targetVm | Select-Object ControllerType,ControllerNumber,ControllerLocation,Path)
        network = @(Get-VMNetworkAdapter -VM $targetVm | Select-Object Name,SwitchName,MacAddress,Status)
    }
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    exit 0
} catch {
    [ordered]@{ success = $false; recorded_at = (Get-Date).ToString('o'); error = $_.Exception.Message } |
        ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding UTF8
    exit 1
}
