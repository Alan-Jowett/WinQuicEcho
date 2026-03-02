# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WinQuicEcho contributors

param(
    [string]$DnsName = "localhost",
    [string]$StoreLocation = "Cert:\CurrentUser\My"
)

$cert = New-SelfSignedCertificate `
    -DnsName $DnsName `
    -CertStoreLocation $StoreLocation `
    -FriendlyName "WinQuicEcho Dev Cert" `
    -NotAfter (Get-Date).AddYears(1) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256

Write-Host "Created certificate:"
Write-Host "  Subject: $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "Use --cert-hash $($cert.Thumbprint) when starting echo_server."
