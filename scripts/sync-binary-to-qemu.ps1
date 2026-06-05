param(
    [string]$Workspace = (Resolve-Path ".").Path,
    [string]$BinaryPath = "target/aarch64-unknown-linux-gnu/release/leo-vc-roaming",
    [int]$SshPort = 2222,
    [string]$Guest = "leo@localhost",
    [string]$RemoteDir = "/home/leo/leo-vc-roaming",
    [string]$RemoteBinaryName = "leo-vc-roaming",
    [string]$IdentityFile = "C:\qemu\aarch64\leo-qemu-key"
)

$ErrorActionPreference = "Stop"

$scp = cmd.exe /c "where scp.exe 2>nul"
if ($LASTEXITCODE -ne 0 -or -not $scp) {
    throw "scp.exe was not found. Install OpenSSH Client in Windows optional features."
}

$ssh = cmd.exe /c "where ssh.exe 2>nul"
if ($LASTEXITCODE -ne 0 -or -not $ssh) {
    throw "ssh.exe was not found. Install OpenSSH Client in Windows optional features."
}

$scp = (($scp -split "`r?`n") | Select-Object -First 1)
$ssh = (($ssh -split "`r?`n") | Select-Object -First 1)

$localBinary = Join-Path $Workspace $BinaryPath

if (-not (Test-Path -LiteralPath $IdentityFile)) {
    throw "SSH identity file not found: $IdentityFile. Run prepare-qemu-ubuntu-arm64.ps1 first."
}

if (-not (Test-Path -LiteralPath $localBinary)) {
    throw "Binary not found: $localBinary. Build it first, e.g. cross build --release --target aarch64-unknown-linux-gnu"
}

Write-Host "Using binary: $localBinary"

& $ssh -i $IdentityFile -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p $SshPort $Guest "mkdir -p $RemoteDir"
if ($LASTEXITCODE -ne 0) {
    throw "SSH key authentication failed while creating $RemoteDir. If this guest was booted before key-based cloud-init was added, rebuild the guest disk or install the public key manually."
}
& $scp -i $IdentityFile -o BatchMode=yes -o StrictHostKeyChecking=accept-new -P $SshPort $localBinary "${Guest}:$RemoteDir/$RemoteBinaryName"
if ($LASTEXITCODE -ne 0) {
    throw "SCP failed while copying $localBinary to ${Guest}:$RemoteDir/$RemoteBinaryName."
}
& $ssh -i $IdentityFile -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p $SshPort $Guest "chmod +x $RemoteDir/$RemoteBinaryName"
if ($LASTEXITCODE -ne 0) {
    throw "SSH key authentication failed while chmod-ing $RemoteDir/$RemoteBinaryName."
}

Write-Host "Synced binary to ${Guest}:$RemoteDir/$RemoteBinaryName"
Write-Host "Run with:"
Write-Host "ssh -i $IdentityFile -p $SshPort $Guest '$RemoteDir/$RemoteBinaryName'"
