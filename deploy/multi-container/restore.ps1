<#
.SYNOPSIS
Restore the /data volume of the multi-container deployment from an archive made by backup.ps1.
.DESCRIPTION
Stops every Qertum container except qertum-apiservice (which supplies the volume), runs the
single-container restore.ps1 against it, and restarts the others in a finally block, also when the
operator declines the confirmation. Redis keeps running. Requires PowerShell 7 (pwsh).
#>
#Requires -Version 7.0
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Archive
)

$ErrorActionPreference = "Stop"
$VolumeContainer = "qertum-apiservice"
$Others = @("qertum-identityservice", "qertum-webfrontend", "qertum-acmeservice", "qertum-estservice", "qertum-queueconsumer")
$Stopped = @()

try {
    foreach ($c in $Others) {
        $running = docker inspect -f '{{.State.Running}}' $c 2>$null
        if ($running -eq "true") {
            Write-Host "Stopping $c..."
            docker stop $c | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "could not stop $c" }
            $Stopped += $c
        }
    }
    & "$PSScriptRoot\..\single-container\restore.ps1" -Archive $Archive -Container $VolumeContainer
    $innerExit = $LASTEXITCODE
}
finally {
    foreach ($c in $Stopped) {
        Write-Host "Restarting $c..."
        docker start $c | Out-Null
    }
}
exit $innerExit
