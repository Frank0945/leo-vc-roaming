param(
    [string]$DiskImage = "C:\qemu\aarch64\noble-server-cloudimg-arm64.img",
    [string]$CloudInitDir = "C:\qemu\aarch64\cloud-init",
    [string]$SshKeyPath = "C:\qemu\aarch64\leo-qemu-key",
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

$prepare = Join-Path $PSScriptRoot "prepare-qemu-ubuntu-arm64.ps1"
$requiredPaths = @(
    $DiskImage,
    (Join-Path $CloudInitDir "user-data"),
    (Join-Path $CloudInitDir "meta-data"),
    $SshKeyPath,
    "$SshKeyPath.pub"
)
$missingPaths = @($requiredPaths | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missingPaths.Count -gt 0) {
    Write-Host "QEMU guest is not fully prepared. Missing:"
    foreach ($path in $missingPaths) {
        Write-Host "  $path"
    }
    Write-Host ""
    Write-Host "Running prepare-qemu-ubuntu-arm64.ps1..."
    $outputDir = Split-Path -Parent $DiskImage
    $diskName = Split-Path -Leaf $DiskImage
    & $prepare `
        -OutputDir $outputDir `
        -DiskImage $diskName `
        -SshKeyPath $SshKeyPath
}

Write-Host "NOVI LLC USA Gen 2 OBC QEMU profile"
Write-Host "  Emulated by QEMU: AMD/Xilinx Versal AI Edge application CPU path"
Write-Host "  QEMU machine:     virt"
Write-Host "  QEMU CPU:         $Cpu"
Write-Host "  QEMU vCPUs:       $Smp"
Write-Host "  Guest:            Ubuntu ARM64 Linux userspace"
Write-Host ""
Write-Host "Platform characteristics recorded as experiment assumptions:"
Write-Host "  Cortex-R5F, FPGA fabric, AI Engines, Vorago Cortex-M4, rad-hard FRAM,"
Write-Host "  SEL immunity, SEU/SEFI mitigation, ECC memory interfaces,"
Write-Host "  redundant boot storage, and actual 0.75W/5-50W power behavior."
Write-Host ""
Write-Host "QEMU cannot faithfully emulate those non-A72 hardware blocks; this run"
Write-Host "measures the VC/BBS+ workload on the closest available A72 Linux path."
Write-Host ""

$runner = Join-Path $PSScriptRoot "run-qemu-ubuntu-arm64.ps1"
& $runner `
    -DiskImage $DiskImage `
    -CloudInitDir $CloudInitDir `
    -Workspace $Workspace `
    -Memory $Memory `
    -Smp $Smp `
    -Cpu $Cpu `
    -SshPort $SshPort `
    -CloudInitPort $CloudInitPort `
    -QemuBinary $QemuBinary `
    -Firmware $Firmware `
    -UseVirtfs:$UseVirtfs
