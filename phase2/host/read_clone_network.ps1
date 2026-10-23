#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
[ordered]@{vm=Get-VM -Name 'KICBA-Phase2-Kernel65' | Select-Object Name,Id,State,Status,Uptime;network=Get-VMNetworkAdapter -VMName 'KICBA-Phase2-Kernel65' | Select-Object Name,MacAddress,IPAddresses,SwitchName;firmware=Get-VMFirmware -VMName 'KICBA-Phase2-Kernel65' | Select-Object SecureBoot,PreferredNetworkBootProtocol,BootOrder} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence/clone_network_read.json') -Encoding utf8
