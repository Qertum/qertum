<#
.SYNOPSIS
Proves that a backup archive restores to a CA that works, without touching the operating container.

.DESCRIPTION
Step 1 (manifest): extracts the archive into a scratch Docker volume, rebuilds the manifest of the extracted files
with manifest.sh and compares it with the manifest written next to the archive. A pass means the archive matches
/data at backup time; it is not tamper protection (see restore-test.sh).
Step 2 (usability): runs Qertum.RestoreCheck from the image of the operating container (or -Image) over the scratch
volume, with the network off and no service started: it opens the database, decrypts a stored secret with the
restored key ring, signs a probe with each online issuer and builds a CRL that lists every revoked certificate.
It does not start the running stack.
The result is written to /data/recovery/last-restore.json of the operating container: "usable" when both steps
passed, "verified" when only the manifest step ran (no image known), "failed" when either step failed. A run that
could not test (exit 2) records nothing. The container is never stopped.
Exit codes: 0 identical and usable, 1 mismatch, an archive that cannot be extracted, or a failed check, 2 could not test.
#>
#Requires -Version 7.0
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Target,

    [string]$Container = "qertum",

    [string]$Image = ""
)

$ErrorActionPreference = "Stop"
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture

# Every "could not test" answer is exit 2; a mismatch is exit 1 and is reported where it is found.
function Stop-CannotTest([string]$Message) {
    [Console]::Error.WriteLine("error: $Message")
    exit 2
}

# Windows PowerShell 5.1 turns a native command's stderr into a terminating error under
# $ErrorActionPreference = Stop, so the calls whose failure is an expected answer run with Continue.
function Test-Docker([string[]]$DockerArgs) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker @DockerArgs *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch { return $false }
    finally { $ErrorActionPreference = $previous }
}

function Read-Manifest([string[]]$Lines) {
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string[]]' ([StringComparer]::Ordinal)
    foreach ($line in $Lines) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        $fields = $line -split '  ', 5
        $map[$fields[4]] = $fields[0..3]
    }
    return ,$map
}

$RecordHelper = 'set -e; mkdir -p /data/recovery; chmod 755 /data/recovery; if [ -n "$STEP" ]; then printf ''{\042schemaVersion\042:1,\042kind\042:\042%s\042,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042step\042:\042%s\042,\042failedCheck\042:\042%s\042,\042reportedBy\042:\042%s\042}\n'' "$KIND" "$COMPLETED" "$ARCHIVE" "$STEP" "$CHECK" "$BY" > /data/recovery/last-restore.json.tmp; else printf ''{\042schemaVersion\042:1,\042kind\042:\042%s\042,\042completedAtUtc\042:\042%s\042,\042archiveName\042:\042%s\042,\042reportedBy\042:\042%s\042}\n'' "$KIND" "$COMPLETED" "$ARCHIVE" "$BY" > /data/recovery/last-restore.json.tmp; fi; chmod 644 /data/recovery/last-restore.json.tmp; mv /data/recovery/last-restore.json.tmp /data/recovery/last-restore.json'

# Writes last-restore.json on the operating container's volume. Kind: usable, verified, or failed (Step and Check then name what failed).
function Write-RestoreRecord([string]$Kind, [string]$Step = "", [string]$Check = "") {
    if (-not (Test-Docker @('inspect', $Container))) {
        Write-Warning "Container '$Container' not found, so nothing was recorded for the Qertum dashboard."
        return
    }
    $CompletedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant)
    $SafeName = $ArchiveName -replace '[^A-Za-z0-9._-]', '_'
    docker run --rm --volumes-from $Container `
      -e "KIND=$Kind" -e "STEP=$Step" -e "CHECK=$Check" -e "BY=restore-test.ps1" `
      -e "COMPLETED=$CompletedAt" -e "ARCHIVE=$SafeName" `
      alpine sh -c $RecordHelper
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "The result could not be recorded for the Qertum dashboard."
    }
}

if (-not (Test-Docker @('info'))) { Stop-CannotTest "The Docker daemon is not reachable." }

if (Test-Path -LiteralPath $Target -PathType Container) {
    # Newest archive that has a manifest; a newer one without it is skipped. "Newest" is by name, which
    # carries the UTC time of the backup; a copy off-box or a touch changes the modified time.
    $found = Get-ChildItem -LiteralPath $Target -Filter 'qertum-backup-*.tar.gz' -File |
        Sort-Object Name -Descending |
        Where-Object { Test-Path -LiteralPath ($_.FullName -replace '\.tar\.gz$', '.manifest') } |
        Select-Object -First 1
    if (-not $found) { Stop-CannotTest "No archive with a manifest in $Target." }
    $ArchivePath = $found.FullName
}
elseif (Test-Path -LiteralPath $Target -PathType Leaf) {
    $ArchivePath = (Resolve-Path -LiteralPath $Target).Path
}
else {
    Stop-CannotTest "Not found: $Target"
}

if ($ArchivePath -notmatch '\.tar\.gz$') { Stop-CannotTest "$ArchivePath is not a .tar.gz archive." }
$ManifestPath = $ArchivePath -replace '\.tar\.gz$', '.manifest'
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    Stop-CannotTest "No manifest next to $ArchivePath (expected $ManifestPath); a backup taken before manifests existed cannot be verified."
}

# Convert backslashes to forward slashes for Docker volume mounting compatibility
$ArchiveDir = (Split-Path -Parent $ArchivePath) -replace '\\', '/'
$ArchiveName = Split-Path -Leaf $ArchivePath
$ManifestScript = (Join-Path $PSScriptRoot 'manifest.sh') -replace '\\', '/'
$Volume = "qertum-restore-test-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ", $Invariant) + "-" + $PID

try {
    docker volume create $Volume | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-CannotTest "Could not create the scratch volume." }

    Write-Host "Extracting $ArchiveName into scratch volume $Volume..."
    docker run --rm -v "${Volume}:/data" -v "${ArchiveDir}:/backup:ro" alpine tar xzf "/backup/$ArchiveName" -C /
    if ($LASTEXITCODE -ne 0) {
        # 125, 126 and 127 are docker's own failures (it could not start the container); anything else is tar's.
        if (@(125, 126, 127) -contains $LASTEXITCODE) {
            Stop-CannotTest "docker could not run the extraction (exit $LASTEXITCODE)."
        }
        [Console]::Error.WriteLine("FAILED: the archive could not be extracted; it is damaged or incomplete")
        Write-RestoreRecord 'failed' 'manifest' 'archive'
        exit 1
    }

    $actualLines = docker run --rm -v "${Volume}:/data:ro" -v "${ManifestScript}:/manifest.sh:ro" alpine sh /manifest.sh
    if ($LASTEXITCODE -ne 0) { Stop-CannotTest "Could not read the extracted files." }

    $expected = Read-Manifest (Get-Content -LiteralPath $ManifestPath)
    $actual = Read-Manifest $actualLines
    $diffs = New-Object System.Collections.Generic.List[string]
    foreach ($path in $actual.Keys) {
        if (-not $expected.ContainsKey($path)) { $diffs.Add("extra    $path"); continue }
        $e = $expected[$path]
        $a = $actual[$path]
        if ($a[0] -ne $e[0]) { $diffs.Add("content  $path") }
        if ($a[1] -ne $e[1]) { $diffs.Add("mode     $path ($($e[1]) -> $($a[1]))") }
        if ($a[2] -ne $e[2]) { $diffs.Add("owner    $path ($($e[2]) -> $($a[2]))") }
    }
    foreach ($path in $expected.Keys) {
        if (-not $actual.ContainsKey($path)) { $diffs.Add("missing  $path") }
    }

    if ($diffs.Count -gt 0) {
        [Console]::Error.WriteLine("FAILED: $ArchiveName does not match its manifest ($($diffs.Count) differences):")
        $diffs | Sort-Object | ForEach-Object { [Console]::Error.WriteLine("  $_") }
        Write-RestoreRecord 'failed' 'manifest' 'manifest'
        exit 1
    }

    Write-Host "Verified: $ArchiveName matches its manifest ($($expected.Count) files)."

    # Step 2: open the restored copy offline. The image defaults to the operating container's own.
    if (-not $Image -and (Test-Docker @('inspect', $Container))) {
        $Image = (docker inspect -f '{{.Config.Image}}' $Container)
    }
    if (-not $Image) {
        Write-Warning "No image to open the restored copy with (container '$Container' not found and no -Image); only the manifest was checked."
        Write-RestoreRecord 'verified'
        exit 0
    }

    Write-Host "Opening the restored copy offline with $Image (no network, no services)..."
    $CheckOut = docker run --rm --network none --user 1654:1654 -v "${Volume}:/data" --entrypoint dotnet $Image /app/restorecheck/Qertum.RestoreCheck.dll /data
    $CheckStatus = $LASTEXITCODE
    $CheckOut | ForEach-Object { Write-Host $_ }

    if ($CheckStatus -eq 0) {
        Write-Host "Usable: the restored copy was opened offline and the checks above passed."
        # A check with nothing to test (no encrypted secret, no online issuer, a CA never onboarded) is not a pass.
        $NotExercised = ($CheckOut | Where-Object { $_ -match '^check \S+ not-exercised ' } | ForEach-Object { ($_ -split ' ')[1] }) -join ' '
        if ($NotExercised) {
            Write-Warning "not exercised: $NotExercised - 'usable' says nothing about those."
        }
        Write-RestoreRecord 'usable'
    }
    elseif ($CheckStatus -eq 1) {
        $line = $CheckOut | Where-Object { $_ -match '^check \S+ fail ' } | Select-Object -First 1
        $FailedCheck = if ($line) { (($line -split ' ')[1]) -replace '[^A-Za-z0-9._:-]', '_' } else { 'usability' }
        $FailedCheck = $FailedCheck.Substring(0, [Math]::Min(32, $FailedCheck.Length))
        [Console]::Error.WriteLine("FAILED: the restored copy does not work (check: $FailedCheck)")
        Write-RestoreRecord 'failed' 'usability' $FailedCheck
        exit 1
    }
    else {
        Stop-CannotTest "The restored copy could not be tested with $Image (exit $CheckStatus); an image older than the check has no Qertum.RestoreCheck."
    }
}
finally {
    # Remove the scratch volume (docker volume rm), whether or not the test passed. It holds a copy of /data,
    # CA private keys included: say so if it cannot be removed.
    if (-not (Test-Docker @('volume', 'rm', '-f', $Volume))) {
        Write-Warning "could not remove the scratch volume $Volume; it holds a copy of the backup, so remove it with: docker volume rm $Volume"
    }
}
