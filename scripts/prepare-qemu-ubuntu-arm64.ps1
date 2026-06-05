param(
    [string]$OutputDir = "C:\qemu\aarch64",
    [string]$ImageUrl = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
    [string]$DiskImage = "noble-server-cloudimg-arm64.img",
    [string]$DiskSize = "20G",
    [string]$SshKeyPath = (Join-Path $OutputDir "leo-qemu-key")
)

$ErrorActionPreference = "Stop"

function Find-Executable {
    param([string[]]$Names)

    foreach ($name in $Names) {
        $result = cmd.exe /c "where $name 2>nul"
        if ($LASTEXITCODE -eq 0 -and $result) {
            return (($result -split "`r?`n") | Select-Object -First 1)
        }
    }
    return $null
}

$qemuImg = Find-Executable @("qemu-img.exe", "qemu-img")
if (-not $qemuImg) {
    $candidate = Join-Path ${env:ProgramFiles} "qemu\qemu-img.exe"
    if (Test-Path $candidate) {
        $qemuImg = (Resolve-Path $candidate).Path
    }
}
if (-not $qemuImg) {
    throw "qemu-img was not found. Install QEMU or add C:\Program Files\qemu to PATH."
}

$curl = Find-Executable @("curl.exe", "curl")
if (-not $curl) {
    throw "curl was not found."
}

$sshKeygen = Find-Executable @("ssh-keygen.exe", "ssh-keygen")
if (-not $sshKeygen) {
    throw "ssh-keygen was not found."
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$diskPath = Join-Path $OutputDir $DiskImage

if (-not (Test-Path $diskPath)) {
    Write-Host "Downloading Ubuntu ARM64 cloud image..."
    & $curl -L --fail --output $diskPath $ImageUrl
} else {
    Write-Host "Disk image already exists: $diskPath"
}

Write-Host "Resizing cloud disk to $DiskSize..."
& $qemuImg resize $diskPath $DiskSize

$cloudInitDir = Join-Path $OutputDir "cloud-init"
New-Item -ItemType Directory -Force -Path $cloudInitDir | Out-Null

if (-not (Test-Path -LiteralPath $SshKeyPath)) {
    Write-Host "Generating SSH key pair for guest access..."
    & cmd.exe /c "`"$sshKeygen`" -t ed25519 -N `"`" -f `"$SshKeyPath`""
}

$publicKeyPath = "$SshKeyPath.pub"
if (-not (Test-Path -LiteralPath $publicKeyPath)) {
    throw "SSH public key not found: $publicKeyPath"
}

$publicKey = (Get-Content -Raw $publicKeyPath).Trim()

$userData = @"
#cloud-config
hostname: leo-qemu-a72
manage_etc_hosts: true
ssh_pwauth: false
users:
  - default
  - name: leo
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $publicKey
package_update: true
packages:
  - build-essential
  - ca-certificates
  - curl
  - git
  - pkg-config
  - libssl-dev
  - mount
runcmd:
  - [ sh, -lc, 'curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal' ]
  - [ sh, -lc, 'echo "leo ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-leo' ]
  - [ sh, -lc, 'chmod 0440 /etc/sudoers.d/90-leo' ]
final_message: "LEO QEMU guest is ready. Login with SSH key as leo."
"@

$metaData = @'
instance-id: leo-vc-roaming-qemu
local-hostname: leo-qemu-a72
'@

Set-Content -Encoding ASCII -Path (Join-Path $cloudInitDir "user-data") -Value $userData
Set-Content -Encoding ASCII -Path (Join-Path $cloudInitDir "meta-data") -Value $metaData

Write-Host ""
Write-Host "Prepared ARM64 QEMU guest files:"
Write-Host "  Disk:       $diskPath"
Write-Host "  CloudInit:  $cloudInitDir"
Write-Host "  SSH key:    $SshKeyPath"
Write-Host ""
Write-Host "Next:"
Write-Host "  .\scripts\run-qemu-novi-gen2-obc.ps1 -DiskImage `"$diskPath`" -CloudInitDir `"$cloudInitDir`""
