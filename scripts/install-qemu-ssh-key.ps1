param(
    [int]$SshPort = 2222,
    [string]$Guest = "leo@localhost",
    [string]$IdentityFile = "C:\qemu\aarch64\leo-qemu-key"
)

$ErrorActionPreference = "Stop"

$ssh = cmd.exe /c "where ssh.exe 2>nul"
if ($LASTEXITCODE -ne 0 -or -not $ssh) {
    throw "ssh.exe was not found. Install OpenSSH Client in Windows optional features."
}
$ssh = (($ssh -split "`r?`n") | Select-Object -First 1)

$publicKeyPath = "$IdentityFile.pub"
if (-not (Test-Path -LiteralPath $publicKeyPath)) {
    throw "SSH public key not found: $publicKeyPath. Run prepare-qemu-ubuntu-arm64.ps1 first."
}

$publicKey = (Get-Content -Raw $publicKeyPath).Trim()
$escapedPublicKey = $publicKey.Replace("'", "'\''")
$installCommand = "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && grep -qxF '$escapedPublicKey' ~/.ssh/authorized_keys || echo '$escapedPublicKey' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

Write-Host "Installing SSH public key into $Guest."
Write-Host "You may be asked for the guest password once if this VM was created before key-based login."
& $ssh -o PreferredAuthentications=password,keyboard-interactive,publickey -o StrictHostKeyChecking=accept-new -p $SshPort $Guest $installCommand
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install SSH key into $Guest."
}

Write-Host "Installed SSH key. Future sync commands should not ask for a password."
