param(
    [string]$DiskImage = "C:\qemu\aarch64\noble-server-cloudimg-arm64.img",
    [string]$CloudInitDir = "C:\qemu\aarch64\cloud-init",
    [string]$Workspace = (Resolve-Path ".").Path,
    [string]$Memory = "2048M",
    [int]$Smp = 2,
    [string]$Cpu = "cortex-a72",
    [int]$SshPort = 2222,
    [int]$CloudInitPort = 8000,
    [string]$QemuBinary,
    [string]$Firmware,
    [switch]$UseVirtfs
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

function Resolve-QemuBinary {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path $ExplicitPath) {
            return (Resolve-Path $ExplicitPath).Path
        }
        throw "QEMU binary not found: $ExplicitPath"
    }

    $candidate = Join-Path ${env:ProgramFiles} "qemu\qemu-system-aarch64.exe"
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }

    $pathQemu = Find-Executable @("qemu-system-aarch64.exe", "qemu-system-aarch64")
    if ($pathQemu) {
        return $pathQemu
    }

    throw "qemu-system-aarch64 was not found. Pass -QemuBinary or add QEMU to PATH."
}

function Resolve-Firmware {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path $ExplicitPath) {
            return (Resolve-Path $ExplicitPath).Path
        }
        throw "AArch64 UEFI firmware not found: $ExplicitPath"
    }

    $candidate = Join-Path ${env:ProgramFiles} "qemu\share\edk2-aarch64-code.fd"
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }

    throw "edk2-aarch64-code.fd was not found. Pass -Firmware explicitly."
}

$qemu = Resolve-QemuBinary $QemuBinary
$firmwarePath = Resolve-Firmware $Firmware
$disk = Resolve-Path $DiskImage
$cloudInit = Resolve-Path $CloudInitDir
$share = Resolve-Path $Workspace
$python = Find-Executable @("python.exe", "py.exe", "python")
if (-not $python) {
    throw "Python was not found. It is needed to serve cloud-init metadata to the guest."
}

$httpArgs = @()
if ((Split-Path -Leaf $python) -ieq "py.exe") {
    $httpArgs += @("-3")
}
$httpArgs += @("-m", "http.server", "$CloudInitPort", "--bind", "127.0.0.1", "--directory", "$cloudInit")

Write-Host "Starting cloud-init metadata server on http://127.0.0.1:$CloudInitPort/"
$httpServer = Start-Process -FilePath $python -ArgumentList $httpArgs -PassThru -WindowStyle Hidden

try {
    Write-Host "NOVI Gen 2 OBC Ubuntu ARM64 QEMU profile"
    Write-Host "  CPU:       $Cpu"
    Write-Host "  SMP:       $Smp"
    Write-Host "  Memory:    $Memory"
    Write-Host "  Machine:   virt"
    Write-Host "  Disk:      $disk"
    Write-Host "  SSH:       ssh leo@localhost -p $SshPort"
    Write-Host "  Identity:  C:\qemu\aarch64\leo-qemu-key"
    if ($UseVirtfs) {
        Write-Host "  Share:     $share"
    } else {
        Write-Host "  Share:     disabled; this QEMU build may not support virtfs on Windows"
    }
    Write-Host ""
    Write-Host "After the first boot finishes, open another PowerShell and copy the repo:"
    Write-Host "  .\scripts\sync-repo-to-qemu.ps1 -SshPort $SshPort"
    Write-Host ""
    Write-Host "Then login and run:"
    Write-Host "  ssh -i C:\qemu\aarch64\leo-qemu-key leo@localhost -p $SshPort"
    Write-Host "  cd ~/leo-vc-roaming"
    Write-Host "  source ~/.cargo/env"
    Write-Host "  cargo run --release"
    Write-Host ""

    $qemuArgs = @(
        "-machine", "virt",
        "-cpu", $Cpu,
        "-smp", "$Smp",
        "-m", $Memory,
        "-nographic",
        "-no-reboot",
        "-drive", "if=pflash,format=raw,readonly=on,file=$firmwarePath",
        "-drive", "file=$disk,format=qcow2,if=virtio",
        "-netdev", "user,id=net0,hostfwd=tcp::$SshPort-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-smbios", "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:$CloudInitPort/"
    )
    if ($UseVirtfs) {
        $qemuArgs += @(
            "-virtfs",
            "local,path=$share,mount_tag=hostshare,security_model=none,id=hostshare"
        )
    }

    & $qemu `
        @qemuArgs
}
finally {
    if ($httpServer -and -not $httpServer.HasExited) {
        Stop-Process -Id $httpServer.Id -Force
    }
}
