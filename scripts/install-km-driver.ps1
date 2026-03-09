# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WinQuicEcho contributors

<#
.SYNOPSIS
    Installs (or reinstalls) the WinQuicEcho kernel-mode driver.

.DESCRIPTION
    Copies winquicecho_km.sys to the drivers directory, creates a kernel
    service named "WinQuicEcho", and starts it.  Requires elevation.

    Prerequisites:
      - Test signing enabled (bcdedit /set testsigning on) or a
        production-signed driver.
      - msquic.sys must be installed on the system (dependency).

.PARAMETER SysFile
    Path to the built winquicecho_km.sys file.

.PARAMETER Uninstall
    If set, stops and removes the driver service instead of installing.

.EXAMPLE
    # Install
    .\scripts\install-km-driver.ps1 -SysFile build\km\winquicecho_km.sys

    # Uninstall
    .\scripts\install-km-driver.ps1 -Uninstall
#>

param(
    [string]$SysFile = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$serviceName = "WinQuicEcho"
$driversDir  = "$env:SystemRoot\System32\Drivers"

# Require elevation.
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

function StopAndDeleteService {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        if ($svc.Status -eq 'Running') {
            Write-Host "Stopping service $serviceName ..."
            & sc.exe stop $serviceName | Out-Null
            Start-Sleep -Seconds 2
        }
        Write-Host "Deleting service $serviceName ..."
        & sc.exe delete $serviceName | Out-Null
    }
}

if ($Uninstall) {
    StopAndDeleteService
    $driverDest = Join-Path $driversDir "winquicecho_km.sys"
    if (Test-Path $driverDest) {
        Remove-Item $driverDest -Force
        Write-Host "Removed $driverDest"
    }
    Write-Host "Driver uninstalled."
    return
}

# Install path.
if ([string]::IsNullOrWhiteSpace($SysFile)) {
    throw "Provide -SysFile <path to winquicecho_km.sys> or -Uninstall."
}
if (-not (Test-Path $SysFile)) {
    throw "File not found: $SysFile"
}

# Stop existing service if present.
StopAndDeleteService

# Copy the driver binary.
$dest = Join-Path $driversDir "winquicecho_km.sys"
Write-Host "Copying $SysFile -> $dest"
Copy-Item -Path $SysFile -Destination $dest -Force

# Create the kernel service with a dependency on msquic.
Write-Host "Creating service $serviceName ..."
& sc.exe create $serviceName `
    type= kernel `
    binPath= $dest `
    start= demand `
    depend= msquic
if ($LASTEXITCODE -ne 0) {
    throw "sc create failed with exit code $LASTEXITCODE"
}

# Start the service.
Write-Host "Starting service $serviceName ..."
& sc.exe start $serviceName
if ($LASTEXITCODE -ne 0) {
    throw "sc start failed with exit code $LASTEXITCODE. Check 'bcdedit /set testsigning on' and reboot."
}

Write-Host ""
Write-Host "Driver installed and running. Use --backend msquic-km with echo_server."
