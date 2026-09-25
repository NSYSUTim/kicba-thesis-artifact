[CmdletBinding()]
param(
    [switch]$SkipZip
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir '..'))
$deliverablesRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'deliverables'))
$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $deliverablesRoot 'KICBA_AI_REVIEW_CURRENT'))
$zipPath = [System.IO.Path]::GetFullPath((Join-Path $deliverablesRoot 'KICBA_AI_REVIEW_CURRENT.zip'))

if (-not $outputRoot.StartsWith($deliverablesRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to build outside deliverables: $outputRoot"
}

function Get-SourcePath([string]$RelativePath) {
    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath))
}

function Get-DestinationPath([string]$RelativePath) {
    return [System.IO.Path]::GetFullPath((Join-Path $outputRoot $RelativePath))
}

function Copy-CanonicalFile([string]$SourceRelative, [string]$DestinationRelative = $SourceRelative) {
    $source = Get-SourcePath $SourceRelative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing canonical file: $SourceRelative"
    }
    $destination = Get-DestinationPath $DestinationRelative
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

function Copy-CanonicalTree([string]$SourceRelative, [string]$DestinationRelative = $SourceRelative) {
    $source = Get-SourcePath $SourceRelative
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Missing canonical directory: $SourceRelative"
    }
    $destination = Get-DestinationPath $DestinationRelative
    if (-not $destination.StartsWith($outputRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Tree destination escaped generated output: $destination"
    }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse -Force

    # Remove only cache/history metadata copied into the verified generated tree.
    $excludedDirectories = Get-ChildItem -LiteralPath $destination -Recurse -Directory -Force |
        Where-Object { $_.Name -in @('__pycache__', '.git') } |
        Sort-Object FullName -Descending
    foreach ($excluded in $excludedDirectories) {
        if (-not $excluded.FullName.StartsWith($outputRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Excluded directory escaped generated output: $($excluded.FullName)"
        }
        Remove-Item -LiteralPath $excluded.FullName -Recurse -Force
    }
    foreach ($compiledFile in Get-ChildItem -LiteralPath $destination -Recurse -File -Filter '*.pyc') {
        Remove-Item -LiteralPath $compiledFile.FullName -Force
    }
}

function Assert-SameFile([string]$SourceRelative, [string]$DestinationRelative) {
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Get-SourcePath $SourceRelative)).Hash
    $destinationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Get-DestinationPath $DestinationRelative)).Hash
    if ($sourceHash -ne $destinationHash) {
        throw "Generated copy differs from canonical source: $SourceRelative"
    }
}

function Copy-CanonicalMetadataTree([string]$SourceRelative, [string]$DestinationRelative = $SourceRelative) {
    $source = Get-SourcePath $SourceRelative
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Missing canonical directory: $SourceRelative"
    }
    $sourcePrefix = $source.TrimEnd('\', '/')
    foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File) {
        if ($file.FullName -match '[\\/](__pycache__|\.git)[\\/]' -or
            $file.FullName -match '[\\/][^\\/]*_fixture[\\/]' -or
            [string]::IsNullOrEmpty($file.Extension) -or
            $file.Extension -in @('.gz', '.npz', '.zip', '.pyc') -or
            $file.Name -like 'batch_*') {
            continue
        }
        $relativeWithinTree = $file.FullName.Substring($sourcePrefix.Length).TrimStart('\', '/')
        $destinationRelativePath = Join-Path $DestinationRelative $relativeWithinTree
        $destination = Get-DestinationPath $destinationRelativePath
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    }
}

New-Item -ItemType Directory -Path $deliverablesRoot -Force | Out-Null
if (Test-Path -LiteralPath $outputRoot) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

# Review-package-only canonical files.
Copy-CanonicalFile 'review/START_HERE.md' 'START_HERE.md'
Copy-CanonicalFile 'review/REPRODUCE.md' 'REPRODUCE.md'
Copy-CanonicalFile 'review/REPRODUCTION_VERIFICATION.md' 'REPRODUCTION_VERIFICATION.md'
Copy-CanonicalFile 'docs/DATASET_AND_EVIDENCE_MAP_zh-TW.md' 'DATASET_AND_CODE_MANIFEST.md'
Copy-CanonicalFile 'README.md' 'README.md'
Copy-CanonicalFile 'STATUS.md' 'STATUS.md'

# Current papers, current/frozen protocols, and review provenance.
Copy-CanonicalTree 'docs/papers' 'docs/papers'
Copy-CanonicalTree 'docs/reviews' 'docs/reviews'
foreach ($doc in @(
    'docs/DATASET_AND_EVIDENCE_MAP_zh-TW.md',
    'docs/D6_R2_CONFIRMATORY_PROTOCOL_zh-TW.md',
    'docs/D6_R2_OUTPUT_ERRATUM_zh-TW.md',
    'docs/D6_R2_POST_LOCK_ERRATUM_zh-TW.md',
    'docs/D7_NESTING_CONFIRMATORY_PROTOCOL_zh-TW.md',
    'docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md',
    'docs/D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md',
    'docs/method_provenance_audit_2026-09-20.md',
    'docs/d4_benchmark_correction_protocol.md',
    'docs/D1_D2_explanation.md'
)) {
    Copy-CanonicalFile $doc $doc
}

# Code is copied wholesale from canonical directories; caches are excluded.
foreach ($tree in @('scripts', 'collector', 'src', 'tests', 'attack_variants', 'vm')) {
    Copy-CanonicalTree $tree $tree
}

# Public-data result summaries (D1), confound/failure evidence (D2/D3), and
# development/confirmatory evidence that materially shaped the current papers.
# Raw batch payloads are intentionally omitted; metadata, manifests, audits,
# formal reports, metrics, and predictions are retained.
foreach ($tree in @(
    'results/public_phase',
    'results/d2_formal',
    'results/d3_formal',
    'results/invocation_composition_audit',
    'results/factor_study_d2_d3_development',
    'results/d4_qualification',
    'results/d4_sham_control',
    'results/d4_stable',
    'results/d4_overhead',
    'results/d5_formal',
    'results/d6_formal',
    'results/d6_r2_formal',
    'results/d7_development',
    'results/d7_formal'
)) {
    Copy-CanonicalMetadataTree $tree $tree
}

$provenance = [ordered]@{
    package = 'KICBA_AI_REVIEW_CURRENT'
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    generator = 'scripts/build_ai_review_bundle.ps1'
    canonical_source_policy = 'Edit only workspace canonical sources; never edit deliverables.'
    raw_batch_payloads_included = $false
    raw_data_policy = 'Describe and index canonical datasets; package metadata/reports/code, not raw batches.'
    d1_raw_source = 'Zenodo DOI 10.5281/zenodo.14679675'
}
$provenance | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Get-DestinationPath 'PACKAGE_PROVENANCE.json') -Encoding UTF8

# Verify the two papers and the central evidence map are byte-identical copies.
Assert-SameFile 'docs/papers/TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md' 'docs/papers/TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md'
Assert-SameFile 'docs/papers/TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md' 'docs/papers/TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md'
Assert-SameFile 'docs/DATASET_AND_EVIDENCE_MAP_zh-TW.md' 'DATASET_AND_CODE_MANIFEST.md'
Assert-SameFile 'docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md' 'docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md'
Assert-SameFile 'docs/D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md' 'docs/D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md'

$requiredPackagePaths = @(
    'DATASET_AND_CODE_MANIFEST.md',
    'docs/papers/TRACK_A_LOW_FALSE_POSITIVE_ROOTKIT_zh-TW.md',
    'docs/papers/TRACK_B_SAFE_ONLINE_ADAPTATION_zh-TW.md',
    'results/d5_formal/confirmatory_r1/report.json',
    'results/d6_r2_formal/formal_boot_view_r1_provenance.json',
    'results/d6_r2_formal/confirmatory_r1_output_erratum/report.json',
    'results/d7_development/mechanism_r2_analysis/report.json',
    'results/d7_development/composition_pilot_r1_audit/report.json',
    'results/d7_development/nesting_pilot_r1_reaudit/report.json',
    'docs/D7_NESTING_CONFIRMATORY_PROTOCOL_zh-TW.md',
    'docs/D7_R1_CONFIRMATORY_RESULTS_zh-TW.md',
    'docs/D7_R1_INPUT_LAYOUT_ERRATUM_zh-TW.md',
    'results/d7_formal/analysis_lock.json',
    'results/d7_formal/audit_r1/audit.json',
    'results/d7_formal/analysis_amendment_01.json',
    'results/d7_formal/canonical_view_manifest.json',
    'results/d7_formal/audit_r1_canonical/audit.json',
    'results/d7_formal/confirmatory_r1/report.json',
    'results/d7_formal/confirmatory_r1/predictions.json'
)
foreach ($required in $requiredPackagePaths) {
    if (-not (Test-Path -LiteralPath (Get-DestinationPath $required))) {
        throw "Generated package is missing required evidence: $required"
    }
}

# Fail closed if a future source-tree change accidentally copies raw payloads.
$forbiddenRawFiles = Get-ChildItem -LiteralPath $outputRoot -Recurse -File |
    Where-Object {
        $_.Name -like 'batch_*' -or
        $_.Extension -in @('.gz', '.npz', '.zip', '.pyc') -or
        $_.FullName -match '[\\/][^\\/]*_fixture[\\/]'
    }
if ($forbiddenRawFiles) {
    $forbiddenList = ($forbiddenRawFiles.FullName -join [Environment]::NewLine)
    throw "Generated package unexpectedly contains raw payloads:`n$forbiddenList"
}

$hashRows = foreach ($file in Get-ChildItem -LiteralPath $outputRoot -Recurse -File | Sort-Object FullName) {
    if ($file.Name -eq 'FILE_SHA256.csv') {
        continue
    }
    [pscustomobject]@{
        path = $file.FullName.Substring($outputRoot.Length).TrimStart('\', '/').Replace('\', '/')
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        bytes = $file.Length
    }
}
$hashRows | Export-Csv -LiteralPath (Get-DestinationPath 'FILE_SHA256.csv') -NoTypeInformation -Encoding UTF8

if (-not $SkipZip) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
    $archive = New-Object System.IO.Compression.ZipArchive(
        $zipStream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false
    )
    try {
        foreach ($file in Get-ChildItem -LiteralPath $outputRoot -Recurse -File | Sort-Object FullName) {
            $entryName = $file.FullName.Substring($outputRoot.Length).TrimStart('\', '/').Replace('\', '/')
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive,
                $file.FullName,
                $entryName,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
    }
    finally {
        $archive.Dispose()
        $zipStream.Dispose()
    }
}

$fileCount = (Get-ChildItem -LiteralPath $outputRoot -Recurse -File).Count
$totalBytes = (Get-ChildItem -LiteralPath $outputRoot -Recurse -File | Measure-Object Length -Sum).Sum
Write-Output "Built $outputRoot"
Write-Output 'Mode raw_batch_payloads_included=False'
Write-Output "Files=$fileCount Bytes=$totalBytes"
if (-not $SkipZip) {
    Write-Output "ZIP=$zipPath"
}
