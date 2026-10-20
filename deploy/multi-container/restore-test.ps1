<#
.SYNOPSIS
Verify a backup archive of the multi-container deployment: manifest, then an offline open of the restored copy. Stops nothing.
.DESCRIPTION
Runs the single-container restore-test.ps1 against qertum-apiservice. -Image <ref> overrides the image used for the
offline check (default: the image of qertum-apiservice). Exit codes: 0 identical and usable, 1 mismatch, an archive
that cannot be extracted, or a failed check, 2 could not test. Requires PowerShell 7 (pwsh).
#>
#Requires -Version 7.0
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Target,

    [string]$Image = ""
)

# A parameter-binding error must end the script with a failure, not leave $LASTEXITCODE unset and exit 0.
$ErrorActionPreference = "Stop"

# A hashtable splats by name; an array would pass '-Image' as a positional value.
$Rest = @{}
if ($Image) { $Rest['Image'] = $Image }
& "$PSScriptRoot\..\single-container\restore-test.ps1" -Target $Target -Container "qertum-apiservice" @Rest
exit $LASTEXITCODE
