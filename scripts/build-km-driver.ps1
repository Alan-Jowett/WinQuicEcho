# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WinQuicEcho contributors

<#
.SYNOPSIS
    Builds the WinQuicEcho kernel-mode driver (winquicecho_km.sys).

.DESCRIPTION
    Compiles winquicecho_km.c into a WDM kernel driver using the Windows
    Driver Kit (WDK) toolchain.

    Prerequisites:
      - Visual Studio 2022 (or Build Tools) with the "Desktop development
        with C++" workload.
      - Windows Driver Kit (WDK) for Visual Studio 2022.
      - MsQuic kernel-mode headers and import library.  Provide the path
        to a directory containing:
          inc/msquic.h   (MsQuic public header)
          lib/msquic.lib (kernel-mode import library)

    The MsQuic kernel artefacts can be obtained by either:
      a) Building MsQuic from source with kernel mode enabled:
           .\scripts\build.ps1 -Config Release -Tls schannel -Arch x64 -Kernel
      b) Downloading the "Microsoft.Native.Quic.MsQuic.Schannel" NuGet
         package and extracting the "build/native/..." kernel libs.

.PARAMETER MsQuicKernelDir
    Path to a directory that contains inc/msquic.h and lib/msquic.lib
    (kernel-mode import library for msquic.sys).

.PARAMETER OutDir
    Output directory for winquicecho_km.sys.  Defaults to build\km.

.PARAMETER WdkDir
    Override the WDK root (auto-detected from Program Files if omitted).

.EXAMPLE
    .\scripts\build-km-driver.ps1 -MsQuicKernelDir C:\msquic\artifacts\bin\winkernel\x64_Release_schannel
#>

param(
    [Parameter(Mandatory)]
    [string]$MsQuicKernelDir,

    [string]$OutDir = "build\km",

    [string]$WdkDir = ""
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Locate WDK
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($WdkDir)) {
    $wdkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10",
        "$env:ProgramFiles\Windows Kits\10"
    )
    foreach ($root in $wdkRoots) {
        if (Test-Path "$root\Include") {
            $WdkDir = $root
            break
        }
    }
}
if ([string]::IsNullOrWhiteSpace($WdkDir) -or -not (Test-Path $WdkDir)) {
    throw "WDK not found. Install the Windows Driver Kit or pass -WdkDir."
}

# Find the newest WDK version directory.
$wdkVersions = Get-ChildItem "$WdkDir\Include" -Directory | Sort-Object Name -Descending
if ($wdkVersions.Count -eq 0) {
    throw "No WDK version directories found under $WdkDir\Include."
}
$wdkVer = $wdkVersions[0].Name
Write-Host "Using WDK $wdkVer at $WdkDir"

# ---------------------------------------------------------------------------
# Validate MsQuic kernel artefacts
# ---------------------------------------------------------------------------
$mqInclude = $null
foreach ($candidate in @(
    (Join-Path $MsQuicKernelDir "inc"),
    (Join-Path $MsQuicKernelDir "include"),
    $MsQuicKernelDir
)) {
    if (Test-Path (Join-Path $candidate "msquic.h")) {
        $mqInclude = $candidate
        break
    }
}
if ($null -eq $mqInclude) {
    throw "msquic.h not found under $MsQuicKernelDir (looked in inc/, include/, and root)."
}

$mqLib = $null
foreach ($candidate in @(
    (Join-Path $MsQuicKernelDir "lib"),
    $MsQuicKernelDir
)) {
    if (Test-Path (Join-Path $candidate "msquic.lib")) {
        $mqLib = Join-Path $candidate "msquic.lib"
        break
    }
}
if ($null -eq $mqLib) {
    throw "msquic.lib (kernel import library) not found under $MsQuicKernelDir."
}

Write-Host "MsQuic header dir : $mqInclude"
Write-Host "MsQuic import lib : $mqLib"

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
$srcDir   = Join-Path $PSScriptRoot "..\src\backends\msquic_km"
$driverC  = Join-Path $srcDir "driver\winquicecho_km.c"
if (-not (Test-Path $driverC)) {
    throw "Driver source not found: $driverC"
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$kmInclude = "$WdkDir\Include\$wdkVer\km"
$sharedInc = "$WdkDir\Include\$wdkVer\shared"
$crtInc    = "$WdkDir\Include\$wdkVer\ucrt"  # minimal CRT for kernel
$kmLib     = "$WdkDir\Lib\$wdkVer\km\x64"

# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------
Write-Host "Compiling winquicecho_km.c ..."
$clArgs = @(
    "/c", "/kernel", "/W4", "/WX",
    "/D_KERNEL_MODE", "/DNDIS_MINIPORT_DRIVER=0",
    "/D_AMD64_", "/DAMD64",
    "/I`"$kmInclude`"",
    "/I`"$sharedInc`"",
    "/I`"$crtInc`"",
    "/I`"$mqInclude`"",
    "/I`"$srcDir`"",
    "/Fo`"$OutDir\winquicecho_km.obj`"",
    "`"$driverC`""
)
& cl.exe @clArgs
if ($LASTEXITCODE -ne 0) { throw "Compilation failed." }

# ---------------------------------------------------------------------------
# Link
# ---------------------------------------------------------------------------
Write-Host "Linking winquicecho_km.sys ..."
$linkArgs = @(
    "/DRIVER:WDM", "/SUBSYSTEM:NATIVE", "/ENTRY:DriverEntry",
    "/OUT:`"$OutDir\winquicecho_km.sys`"",
    "/LIBPATH:`"$kmLib`"",
    "ntoskrnl.lib", "hal.lib", "ntstrsafe.lib",
    "`"$mqLib`"",
    "`"$OutDir\winquicecho_km.obj`""
)
& link.exe @linkArgs
if ($LASTEXITCODE -ne 0) { throw "Linking failed." }

Write-Host ""
Write-Host "Built successfully: $OutDir\winquicecho_km.sys"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Enable test signing:   bcdedit /set testsigning on"
Write-Host "  2. Reboot if not already in test-signing mode."
Write-Host "  3. Install the driver:    .\scripts\install-km-driver.ps1 -SysFile $OutDir\winquicecho_km.sys"
