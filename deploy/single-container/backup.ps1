<#
.SYNOPSIS
Backups the Qertum /data volume to a single timestamped tar.gz.

.DESCRIPTION
SQLite and the CA files are not safe to tar while being written, so this stops
the container for the duration of the archive, then restarts it. Runs against
any container created from deploy/single-container via docker run --volumes-from.
#>
#Requires -Version 7.0
param (
    [string]$OutputDir = ".",
    [string]$Container = "qertum"
)

$ErrorActionPreference = "Stop"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$ArchiveName = "qertum-backup-$Timestamp.tar.gz"

if (!(Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$OutputFullPath = (Resolve-Path -Path $OutputDir).Path
# Convert backslashes to forward slashes for Docker volume mounting compatibility
$OutputFullPath = $OutputFullPath -replace '\\', '/'

$containerExists = docker inspect $Container 2>$null
if (-not $?) {
    Write-Error "Container '$Container' not found."
    exit 1
}

$wasRunning = $false
$isRunning = docker inspect -f '{{.State.Running}}' $Container
if ($isRunning -eq 'true') {
    $wasRunning = $true
    Write-Host "Stopping $Container for a consistent backup..."
    docker stop $Container | Out-Null
}

try {
    # A manifest of /data for restore-test.ps1 (see backup.sh). Written as UTF-8 without a BOM and with LF
    # line endings: Windows PowerShell's > redirection would write UTF-16 and CRLF, which would never match
    # the manifest a Linux restore test computes.
    $ManifestName = $ArchiveName -replace '\.tar\.gz$', '.manifest'
    $ManifestScript = (Join-Path $PSScriptRoot 'manifest.sh') -replace '\\', '/'
    Write-Host "Writing integrity manifest $OutputDir\$ManifestName"
    $manifestLines = docker run --rm --volumes-from $Container -v "${ManifestScript}:/manifest.sh:ro" alpine sh /manifest.sh
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "The backup continues, but no integrity manifest could be written, so restore-test.ps1 cannot verify it."
    }
    else {
        $manifestText = (($manifestLines | ForEach-Object { $_ }) -join "`n") + "`n"
        [System.IO.File]::WriteAllText((Join-Path $OutputFullPath $ManifestName), $manifestText, (New-Object System.Text.UTF8Encoding($false)))
    }

    Write-Host "Archiving /data from $Container -> $OutputDir\$ArchiveName"
    docker run --rm `
      --volumes-from $Container `
      -v "${OutputFullPath}:/backup" `
      alpine tar czf "/backup/$ArchiveName" -C / data
    # PowerShell does not stop on a failing native command. Without this check a partial archive
    # would be recorded as a fresh backup.
    if ($LASTEXITCODE -ne 0) {
        throw "Archiving /data failed (docker exit code $LASTEXITCODE). No backup status was recorded."
    }

    # Tell Qertum's dashboard when this backup finished (see backup.sh). A failure only warns.
    $SizeBytes = (Get-Item -Path (Join-Path $OutputFullPath $ArchiveName)).Length
    $CompletedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    $helper = 'set -e; mkdir -p /data/recovery; chmod 755 /data/recovery; printf ''{\042schemaVersion\042:1,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042sizeBytes\042:%s,\042reportedBy\042:\042%s\042}\n'' $COMPLETED $ARCHIVE $SIZE $BY > /data/recovery/last-backup.json.tmp; chmod 644 /data/recovery/last-backup.json.tmp; mv /data/recovery/last-backup.json.tmp /data/recovery/last-backup.json'
    docker run --rm --volumes-from $Container `
      -e "COMPLETED=$CompletedAt" -e "ARCHIVE=$ArchiveName" -e "SIZE=$SizeBytes" -e "BY=backup.ps1" `
      alpine sh -c $helper
    if (-not $?) {
        Write-Warning "The backup is fine, but its status could not be recorded for the Qertum dashboard."
    }

    Write-Host "Done: $OutputDir\$ArchiveName"
}
finally {
    if ($wasRunning) {
        Write-Host "Restarting $Container..."
        docker start $Container | Out-Null
    }
}
