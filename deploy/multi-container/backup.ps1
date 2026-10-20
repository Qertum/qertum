<#
.SYNOPSIS
Back up the /data volume of the multi-container deployment.
.DESCRIPTION
Stops every Qertum container except qertum-apiservice (which supplies the volume), runs the
single-container backup.ps1 against it, and restarts the others in a finally block.
Redis keeps running. Requires PowerShell 7 (pwsh).
#>
#Requires -Version 7.0
param (
    [string]$OutputDir = "."
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
    & "$PSScriptRoot\..\single-container\backup.ps1" -OutputDir $OutputDir -Container $VolumeContainer
    $innerExit = $LASTEXITCODE
}
finally {
    foreach ($c in $Stopped) {
        Write-Host "Restarting $c..."
        docker start $c | Out-Null
    }
}
exit $innerExit
