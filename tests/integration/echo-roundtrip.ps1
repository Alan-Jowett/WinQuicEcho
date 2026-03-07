# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WinQuicEcho contributors

<#
.SYNOPSIS
    Integration test: starts the echo server, runs the client, and validates
    that QUIC datagrams are echoed back successfully.

.DESCRIPTION
    1. Checks that msquic.dll is available on the system.
    2. Creates a self-signed certificate for the server.
    3. Starts echo_server on a high port.
    4. Runs echo_client for a short duration against the server.
    5. Parses the client stats-file JSON and asserts:
       - requests_sent > 0 (client successfully connected and sent)
       - requests_completed > 0 (server echoed and client received)
    6. Cleans up the server process, certificate, and temp files.

    Exit code 0 = pass, non-zero = fail.  If msquic.dll is absent the test
    exits with code 77 (skip) to avoid CI failures on runners without QUIC.
#>

param(
    [Parameter(Mandatory)]
    [string]$BuildDir,

    [string]$Config = "Release",
    [int]$Port = 0,
    [int]$Duration = 5,
    [int]$Connections = 2,
    [string]$Backend = "msquic"
)

$ErrorActionPreference = "Stop"

# Pick an available ephemeral port when none is specified.
if ($Port -eq 0) {
    $udpClient = [System.Net.Sockets.UdpClient]::new(0)
    try {
        $Port = ([System.Net.IPEndPoint]$udpClient.Client.LocalEndPoint).Port
    } finally {
        $udpClient.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Resolve binary paths - handle empty $Config for single-config generators.
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($Config)) {
    $serverExe = Join-Path $BuildDir "echo_server.exe"
    $clientExe = Join-Path $BuildDir "echo_client.exe"
    if (-not (Test-Path $serverExe)) {
        # Fallback: try Release subdirectory
        $serverExe = Join-Path $BuildDir "Release\echo_server.exe"
        $clientExe = Join-Path $BuildDir "Release\echo_client.exe"
    }
} else {
    $serverExe = Join-Path $BuildDir "$Config\echo_server.exe"
    $clientExe = Join-Path $BuildDir "$Config\echo_client.exe"
    if (-not (Test-Path $serverExe)) {
        # Fallback: try directly in BuildDir (single-config generator)
        $altServer = Join-Path $BuildDir "echo_server.exe"
        if (Test-Path $altServer) {
            $serverExe = $altServer
            $clientExe = Join-Path $BuildDir "echo_client.exe"
        }
    }
}

foreach ($exe in @($serverExe, $clientExe)) {
    if (-not (Test-Path $exe)) {
        throw "Binary not found: $exe"
    }
}

# ---------------------------------------------------------------------------
# Check msquic.dll availability.
# Searched in order:
#   1. Next to the binaries (built from source or placed by CI).
#   2. %SystemRoot%\System32 (Windows 11 / Server 2022+).
# ---------------------------------------------------------------------------
$binaryDir  = Split-Path $serverExe -Parent
$localDll   = Join-Path $binaryDir "msquic.dll"
$systemDll  = Join-Path $env:SystemRoot "System32\msquic.dll"

if (Test-Path $localDll) {
    Write-Host "Found msquic.dll next to binaries: $localDll"
} elseif (Test-Path $systemDll) {
    Write-Host "Found msquic.dll in System32: $systemDll"
} else {
    Write-Warning "Schannel msquic.dll not found - skipping integration test."
    Write-Warning "  Looked in: $localDll"
    Write-Warning "         and: $systemDll"
    exit 77
}

# ---------------------------------------------------------------------------
# Generate a throwaway self-signed certificate via .NET and import it into
# the CurrentUser\My certificate store so we can pass --cert-hash.
# ---------------------------------------------------------------------------
Write-Host "Generating self-signed certificate ..."

$useLocalMachine = $Backend -eq "msquic-km"

if ($useLocalMachine) {
    # Kernel mode uses the LocalMachine store (QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE).
    $persistedCert = New-SelfSignedCertificate `
        -Type SSLServerAuthentication `
        -Subject "CN=localhost" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -NotAfter (Get-Date).AddHours(1)
    $thumbprint = $persistedCert.Thumbprint
    Write-Host "Certificate thumbprint: $thumbprint (imported into LocalMachine\My)"
} else {
    # User mode uses the CurrentUser store.
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=localhost", $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    $oids = [System.Security.Cryptography.OidCollection]::new()
    [void]$oids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1"))
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))

    $cert = $req.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow,
        [System.DateTimeOffset]::UtcNow.AddHours(1))

    $pfxBytes = $cert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "ephemeral")
    $importFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                   [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    $persistedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfxBytes, "ephemeral", $importFlags)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($persistedCert)
    } finally {
        $store.Close()
    }
    $thumbprint = $persistedCert.Thumbprint
    Write-Host "Certificate thumbprint: $thumbprint (imported into CurrentUser\My)"
}

# Temp files (unique per-run directory to avoid collisions)
$tempRunDir = Join-Path $env:TEMP ("echo-test-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempRunDir -Force | Out-Null
$statsFile = Join-Path $tempRunDir "stats.json"
$serverLog = Join-Path $tempRunDir "server.log"
$serverErr = Join-Path $tempRunDir "server-err.log"

$exitCode = 0
try {
    # -----------------------------------------------------------------
    # Start the server
    # -----------------------------------------------------------------
    Write-Host "Starting echo_server on port $Port ..."
    $serverArgs = @(
        "--backend", $Backend,
        "--port", "$Port",
        "--cert-hash", $thumbprint,
        "--duration", "$($Duration + 30)",
        "--verbose"
    )
    $serverProcess = Start-Process `
        -FilePath $serverExe `
        -ArgumentList $serverArgs `
        -PassThru `
        -NoNewWindow `
        -RedirectStandardOutput $serverLog `
        -RedirectStandardError $serverErr

    # Wait for the server to start listening (poll log for readiness)
    $maxWaitSeconds = 30
    $startTime = Get-Date
    $serverReady = $false
    while (((Get-Date) - $startTime).TotalSeconds -lt $maxWaitSeconds) {
        if ($serverProcess.HasExited) {
            break
        }
        if ((Test-Path $serverLog) -and (Select-String -Path $serverLog -Pattern "Listening on" -Quiet)) {
            $serverReady = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $serverReady -and -not $serverProcess.HasExited) {
        # Fallback: if no readiness line found, give it a brief extra moment
        Start-Sleep -Seconds 2
    }

    if ($serverProcess.HasExited) {
        $ec = $serverProcess.ExitCode
        $errText = if (Test-Path $serverErr) { Get-Content $serverErr -Raw } else { "(empty)" }
        $outText = if (Test-Path $serverLog) { Get-Content $serverLog -Raw } else { "(empty)" }
        Write-Host "ERROR: Server exited prematurely (exit code $ec)."
        Write-Host "stdout: $outText"
        Write-Host "stderr: $errText"
        $exitCode = 1
        return
    }
    Write-Host "Server running (PID $($serverProcess.Id))."

    # -----------------------------------------------------------------
    # Run the client
    # -----------------------------------------------------------------
    Write-Host "Running echo_client for $Duration s with $Connections connections ..."
    $clientArgs = @(
        "--backend",      "msquic",
        "--server",       "127.0.0.1",
        "--port",         "$Port",
        "--connections",  "$Connections",
        "--duration",     "$Duration",
        "--insecure",
        "--payload",      "64",
        "--stats-file",   $statsFile,
        "--verbose"
    )
    & $clientExe @clientArgs 2>&1 | ForEach-Object { Write-Host "  [client] $_" }
    $clientExit = $LASTEXITCODE

    if ($clientExit -ne 0) {
        Write-Host "Client exited with code $clientExit"
        # Don't exit immediately - fall through to dump server logs for diagnostics
    }

    # -----------------------------------------------------------------
    # Validate the results
    # -----------------------------------------------------------------

    # Always dump server logs for diagnostics
    Write-Host "`n--- Server stdout (last 50 lines) ---"
    if (Test-Path $serverLog) {
        Get-Content $serverLog | Select-Object -Last 50 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  (no server stdout log)"
    }
    Write-Host "`n--- Server stderr (last 50 lines) ---"
    if (Test-Path $serverErr) {
        Get-Content $serverErr | Select-Object -Last 50 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  (no server stderr log)"
    }

    if (-not (Test-Path $statsFile)) {
        Write-Host "FAIL: Stats file was not created at: $statsFile"
        $exitCode = 1
        return
    }

    $stats = Get-Content $statsFile -Raw | ConvertFrom-Json

    Write-Host ""
    Write-Host "=== Test Results ==="
    Write-Host "  Requests sent:      $($stats.requests_sent)"
    Write-Host "  Requests completed: $($stats.requests_completed)"
    Write-Host "  Errors:             $($stats.errors)"
    Write-Host "  Bytes sent:         $($stats.bytes_sent)"
    Write-Host "  Bytes received:     $($stats.bytes_received)"
    if ($stats.latency_avg_ns) {
        Write-Host "  Latency avg:        $([math]::Round($stats.latency_avg_ns / 1e6, 2)) ms"
    }

    $testFailed = $false

    if ($stats.requests_sent -le 0) {
        Write-Host "FAIL: No requests were sent."
        $testFailed = $true
    }

    if ($stats.requests_completed -le 0) {
        Write-Host "FAIL: No requests were completed (no datagrams echoed back)."
        $testFailed = $true
    }

    if ($testFailed) {
        $exitCode = 1
        return
    }

    $rps = if ($stats.duration_s -gt 0) { [math]::Round($stats.requests_completed / $stats.duration_s, 1) } else { 0 }
    Write-Host ""
    Write-Host "PASS: Echo roundtrip integration test succeeded."
    Write-Host "  Effective RPS: $rps"

} finally {
    # -----------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Write-Host "Stopping server (PID $($serverProcess.Id)) ..."
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    }

    # Remove the test certificate and private key from the store
    if ($thumbprint) {
        try {
            if ($useLocalMachine) {
                certutil -delstore my $thumbprint | Out-Null
                Write-Host "Removed test certificate from LocalMachine\My via certutil."
            } else {
                $certutil = Get-Command certutil.exe -ErrorAction SilentlyContinue
                if ($certutil) {
                    & $certutil.Path -user -delstore my $thumbprint | Out-Null
                    Write-Host "Removed test certificate and private key via certutil."
                } else {
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                        [System.Security.Cryptography.X509Certificates.StoreName]::My,
                        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }
                    if ($found) {
                        foreach ($cert in @($found)) {
                            $store.Remove($cert)
                        }
                    }
                    $store.Close()
                    Write-Host "Removed test certificate from store (certutil not available)."
                }
            }
        } catch {
            Write-Warning "Could not remove test certificate: $_"
        }
    }

    if ($tempRunDir -and (Test-Path $tempRunDir)) {
        Remove-Item $tempRunDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
