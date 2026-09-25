param(
    [string]$IsoPath = "D:\KICBA-Lab\iso\ubuntu-22.04.5-live-server-amd64.iso",
    [string]$VmName = "KICBA-Lab",
    [string]$VmRoot = "D:\KICBA-Lab\vm",
    [string]$StatusPath = "D:\KICBA-Lab\vm_created.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
    throw "Ubuntu ISO not found: $IsoPath"
}
if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
    throw "VM already exists; refusing to overwrite it: $VmName"
}

$switch = Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue
if (-not $switch) {
    $switch = Get-VMSwitch | Where-Object SwitchType -eq "External" | Select-Object -First 1
}
if (-not $switch) {
    throw "No Hyper-V default or external switch is available."
}

New-Item -ItemType Directory -Path $VmRoot -Force | Out-Null
$vhdPath = Join-Path $VmRoot "KICBA-Lab.vhdx"
$vm = New-VM -Name $VmName -Generation 2 -MemoryStartupBytes 8GB `
    -NewVHDPath $vhdPath -NewVHDSizeBytes 60GB -Path $VmRoot `
    -SwitchName $switch.Name

Set-VM -Name $VmName -ProcessorCount 4 -AutomaticCheckpointsEnabled $false
Set-VMMemory -VMName $VmName -DynamicMemoryEnabled $false
Set-VMFirmware -VMName $VmName `
    -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName $VmName -Path $IsoPath
$dvd = Get-VMDvdDrive -VMName $VmName
Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd

$summary = [ordered]@{
    Name = $VmName
    State = $vm.State.ToString()
    Generation = $vm.Generation
    MemoryGB = 8
    ProcessorCount = 4
    VhdPath = $vhdPath
    IsoPath = $IsoPath
    SwitchName = $switch.Name
    IsolationRule = "Disconnect the VM network adapter before loading CARAXES"
}
$summary | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $StatusPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 3
