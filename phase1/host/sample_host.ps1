param([Parameter(Mandatory=$true)][string]$OutputPath,
      [Parameter(Mandatory=$true)][string]$StopFile)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputPath) { throw 'Refusing to overwrite host samples.' }
$sampleStream = New-Object System.IO.StreamWriter($OutputPath, $false, (New-Object System.Text.UTF8Encoding($false)))
try {
    while (-not (Test-Path -LiteralPath $StopFile)) {
        $sample = [ordered]@{ recorded_at_utc = [DateTime]::UtcNow.ToString('o') }
        try {
            $cpu = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
            $memory = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory
            $sample.cpu_percent = [double]$cpu.PercentProcessorTime
            $sample.available_memory_mib = [long]$memory.AvailableMBytes
            $sample.committed_bytes = [long]$memory.CommittedBytes
        } catch { $sample.error = $_.Exception.Message }
        $sampleStream.WriteLine(($sample | ConvertTo-Json -Compress))
        $sampleStream.Flush()
        Start-Sleep -Seconds 1
    }
} finally { $sampleStream.Dispose() }
