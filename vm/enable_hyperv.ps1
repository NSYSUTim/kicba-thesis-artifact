param(
    [string]$StatusPath = (Join-Path $PSScriptRoot "enable_hyperv.status.json")
)

$ErrorActionPreference = "Stop"

try {
    $featureNames = @(
        "Microsoft-Hyper-V-All",
        "Microsoft-Hyper-V-Management-PowerShell"
    )
    $restartNeeded = $false
    $states = @()
    foreach ($featureName in $featureNames) {
        $before = Get-WindowsOptionalFeature -Online -FeatureName $featureName
        Write-Output "Before: $($before.FeatureName)=$($before.State)"
        if ($before.State -ne "Enabled") {
            $result = Enable-WindowsOptionalFeature `
                -Online -FeatureName $featureName -All -NoRestart
            $restartNeeded = $restartNeeded -or $result.RestartNeeded
        }
        $after = Get-WindowsOptionalFeature -Online -FeatureName $featureName
        Write-Output "After: $($after.FeatureName)=$($after.State)"
        $states += [ordered]@{
            FeatureName = $featureName
            Before = $before.State.ToString()
            After = $after.State.ToString()
        }
    }
    Write-Output "RestartNeeded=$restartNeeded"

    [ordered]@{
        Features = $states
        RestartNeeded = [bool]$restartNeeded
        HyperVModulePaths = @(
            Get-Module -ListAvailable Hyper-V | Select-Object -ExpandProperty Path
        )
        VmmsServicePresent = [bool](Get-Service vmms -ErrorAction SilentlyContinue)
        VmConnectPresent = Test-Path -LiteralPath "$env:SystemRoot\System32\vmconnect.exe"
        CompletedUtc = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $StatusPath -Encoding UTF8

    if ($restartNeeded) {
        exit 3010
    }
} catch {
    [ordered]@{
        Error = $_.Exception.Message
        Category = $_.CategoryInfo.Category.ToString()
        ScriptStackTrace = $_.ScriptStackTrace
        FailedUtc = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $StatusPath -Encoding UTF8
    exit 1
}
