<#
.SYNOPSIS
Restore a Qertum /data volume from an archive produced by backup.ps1 or backup.sh.

.DESCRIPTION
The target container must already exist (create it once with
docker compose up first). This script stops it, replaces the contents of
/data, and restarts it.
#>
#Requires -Version 7.0
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Archive,
    
    [string]$Container = "qertum"
)

$ErrorActionPreference = "Stop"

if (!(Test-Path -Path $Archive -PathType Leaf)) {
    Write-Error "Archive not found: $Archive"
    exit 1
}

$ArchiveFullPath = (Resolve-Path -Path $Archive).Path
$ArchiveDir = Split-Path -Parent $ArchiveFullPath
$ArchiveName = Split-Path -Leaf $ArchiveFullPath
# Convert backslashes to forward slashes for Docker volume mounting compatibility
$ArchiveDir = $ArchiveDir -replace '\\', '/'

$containerExists = docker inspect $Container 2>$null
if (-not $?) {
    Write-Error "Container '$Container' not found. Create it once with 'docker compose up' first."
    exit 1
}

Write-Warning "This replaces the current contents of /data in '$Container' with $Archive."
$confirm = Read-Host "Continue? [y/N]"
if ($confirm -notmatch '^[yY]$') {
    Write-Host "Aborted."
    exit 1
}

$wasRunning = $false
$isRunning = docker inspect -f '{{.State.Running}}' $Container
if ($isRunning -eq 'true') {
    $wasRunning = $true
    Write-Host "Stopping $Container..."
    docker stop $Container | Out-Null
}

try {
    # /data/recovery holds this host's own backup records. An archive carries the copy from before it
    # was taken, so it must neither be cleared nor overwritten by the extraction.
    Write-Host "Clearing existing /data (keeping /data/recovery)..."
    docker run --rm --volumes-from $Container alpine sh -c 'find /data -mindepth 1 -maxdepth 1 ! -name recovery -exec rm -rf {} + 2>/dev/null || true'
    if ($LASTEXITCODE -ne 0) {
        throw "Clearing /data failed (docker exit code $LASTEXITCODE). Nothing was restored."
    }

    Write-Host "Restoring $Archive -> /data in $Container"
    docker run --rm `
      --volumes-from $Container `
      -v "${ArchiveDir}:/backup" `
      alpine tar xzf "/backup/$ArchiveName" -C / --exclude=data/recovery --exclude='data/recovery/*'
    if ($LASTEXITCODE -ne 0) {
        throw "Extracting the archive failed (docker exit code $LASTEXITCODE). No restore status was recorded."
    }

    # Record that a restore was performed. It is not a verification (see restore.sh).
    $CompletedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    $SafeName = $ArchiveName -replace '[^A-Za-z0-9._-]', '_'
    $helper = 'set -e; mkdir -p /data/recovery; chmod 755 /data/recovery; printf ''{\042schemaVersion\042:1,\042kind\042:\042performed\042,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042reportedBy\042:\042%s\042}\n'' $COMPLETED $ARCHIVE $BY > /data/recovery/last-restore.json.tmp; chmod 644 /data/recovery/last-restore.json.tmp; mv /data/recovery/last-restore.json.tmp /data/recovery/last-restore.json'
    docker run --rm --volumes-from $Container `
      -e "COMPLETED=$CompletedAt" -e "ARCHIVE=$SafeName" -e "BY=restore.ps1" `
      alpine sh -c $helper
    if (-not $?) {
        Write-Warning "The restore worked, but its status could not be recorded for the Qertum dashboard."
    }
}
finally {
    if ($wasRunning) {
        Write-Host "Starting $Container..."
        docker start $Container | Out-Null
    }
}

Write-Host "Restore complete."
