param(
    [string]$VmName = "KICBA-Lab",
    [string]$StatusPath = "D:\KICBA-Lab\vm_started.json"
)

$ErrorActionPreference = "Stop"
$vm = Get-VM -Name $VmName -ErrorAction Stop
if ($vm.State -eq "Off") {
    Start-VM -Name $VmName | Out-Null
} elseif ($vm.State -ne "Running") {
    throw "VM is in unexpected state: $($vm.State)"
}

$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    Start-Sleep -Milliseconds 500
    $vm = Get-VM -Name $VmName
} until ($vm.State -eq "Running" -or [DateTime]::UtcNow -ge $deadline)

if ($vm.State -ne "Running") {
    throw "VM did not reach Running state within 30 seconds"
}

[ordered]@{
    Name = $vm.Name
    State = $vm.State.ToString()
    UptimeSeconds = [math]::Round($vm.Uptime.TotalSeconds, 1)
    StartedUtc = [DateTime]::UtcNow.ToString("o")
} | ConvertTo-Json | Set-Content -LiteralPath $StatusPath -Encoding UTF8
