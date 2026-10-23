#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][ValidateSet('CreateClone','Original','Clone')][string]$Mode)
$ErrorActionPreference='Stop'
$originalName='KICBA-Lab'
$cloneName='KICBA-Phase2-Kernel65'
$cloneRoot='D:\KICBA-Lab\phase2-20261023'
$evidence=Join-Path $PSScriptRoot 'evidence'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$recordFile=Join-Path $evidence ($Mode+'_'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')
try {
    $original=Get-VM -Name $originalName
    if ($original.Id.ToString() -ne 'd265205d-e394-417d-b629-f0c947341d11') { throw 'Original VM identity mismatch' }
    if ($Mode -eq 'CreateClone') {
        if ((Get-Volume -DriveLetter D).SizeRemaining -lt 70GB) { throw 'Insufficient clone disk space' }
        if (Get-VM -Name $cloneName -ErrorAction SilentlyContinue) { throw 'Clone VM already exists' }
        if (Test-Path -LiteralPath $cloneRoot) { throw 'Clone path exists; refusing overwrite' }
        $disk=@(Get-VMHardDiskDrive -VM $original)
        if ($disk.Count -ne 1) { throw 'Expected one original disk' }
        if ($original.State -ne 'Off') { Stop-VM -VM $original -Confirm:$false }
        if ((Get-VM -Id $original.Id).State -ne 'Off') { throw 'Original did not shut down' }
        New-Item -ItemType Directory -Path $cloneRoot | Out-Null
        $targetDisk=Join-Path $cloneRoot 'kernel65.vhdx'
        Convert-VHD -Path $disk[0].Path -DestinationPath $targetDisk -VHDType Dynamic
        $clone=New-VM -Name $cloneName -Path $cloneRoot -Generation 2 -MemoryStartupBytes 8GB -VHDPath $targetDisk -SwitchName 'KICBA-Isolated'
        Set-VMProcessor -VM $clone -Count 4
        Set-VMFirmware -VM $clone -EnableSecureBoot Off
        Set-VM -VM $clone -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Standard -AutomaticCheckpointsEnabled $false
        Start-VM -VM $clone
    } elseif ($Mode -eq 'Original') {
        $clone=Get-VM -Name $cloneName
        if ($clone.State -ne 'Off') { Stop-VM -VM $clone -Confirm:$false }
        Start-VM -VM $original
    } else {
        $clone=Get-VM -Name $cloneName
        if ($original.State -ne 'Off') { Stop-VM -VM $original -Confirm:$false }
        Start-VM -VM $clone
    }
    [ordered]@{success=$true;mode=$Mode;recorded_at=(Get-Date).ToString('o');
      original=Get-VM -Name $originalName | Select-Object Name,Id,State,MemoryStartup,ProcessorCount;
      clone=Get-VM -Name $cloneName | Select-Object Name,Id,State,MemoryStartup,ProcessorCount;
      clone_disks=Get-VMHardDiskDrive -VMName $cloneName | Select-Object Path} |
      ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $recordFile -Encoding UTF8
} catch {
    if ($Mode -eq 'CreateClone') {
        $failedClone=Get-VM -Name $cloneName -ErrorAction SilentlyContinue
        if (($null -eq $failedClone -or $failedClone.State -eq 'Off') -and (Get-VM -Name $originalName).State -eq 'Off') {
            Start-VM -Name $originalName -ErrorAction SilentlyContinue
        }
    }
    [ordered]@{success=$false;mode=$Mode;recorded_at=(Get-Date).ToString('o');error=$_.Exception.Message} |
      ConvertTo-Json | Set-Content -LiteralPath $recordFile -Encoding UTF8
    exit 1
}
