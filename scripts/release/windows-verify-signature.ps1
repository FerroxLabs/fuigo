# Fails (exit 1) unless the exe has a Valid Authenticode signature from a Ferrox Labs certificate.
param([Parameter(Mandatory = $true)][string]$Path, [string]$Subject = 'Ferrox Labs')
$ErrorActionPreference = 'Stop'
# Self-test: an unsigned file must not come back Valid, or the gate below measures nothing.
$probe = Get-AuthenticodeSignature -FilePath $PSCommandPath
if ($probe.Status -eq 'Valid') { Write-Host "::error::self-test failed: this unsigned script reports a Valid signature"; exit 1 }
Write-Host "self-test: unsigned file reports '$($probe.Status)'"
$sig = Get-AuthenticodeSignature -FilePath $Path
Write-Host "Status:      $($sig.Status)"
if ($sig.SignerCertificate) {
  Write-Host "Subject:     $($sig.SignerCertificate.Subject)"
  Write-Host "Issuer:      $($sig.SignerCertificate.Issuer)"
  Write-Host "Thumbprint:  $($sig.SignerCertificate.Thumbprint)"
}
if ($sig.TimeStamperCertificate) {
  Write-Host "Timestamper: $($sig.TimeStamperCertificate.Subject)"
}
if ($sig.Status -ne 'Valid') { Write-Host "::error::$Path signature status is $($sig.Status), expected Valid"; exit 1 }
if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notlike "*$Subject*") {
  Write-Host "::error::$Path signer subject does not contain '$Subject'"; exit 1
}
if (-not $sig.TimeStamperCertificate) { Write-Host "::error::$Path has no RFC 3161 timestamp"; exit 1 }
