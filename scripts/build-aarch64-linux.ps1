<#
.SYNOPSIS
Builds the release executable for aarch64-unknown-linux-gnu using Docker.

.DESCRIPTION
Builds a reusable Docker image containing Rust, the GNU AArch64 cross-linker,
and the ARM64 glibc development sysroot. The compiled ELF is written to:
target/aarch64-unknown-linux-gnu/release/leo-vc-roaming
#>
[CmdletBinding()]
param(
    [string]$ImageTag = "leo-vc-roaming-aarch64-builder:latest",
    [switch]$SkipImageBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$dockerfile = Join-Path $repoRoot "docker\aarch64-linux-builder.Dockerfile"
$binaryRelativePath = "target/aarch64-unknown-linux-gnu/release/leo-vc-roaming"
$binaryPath = Join-Path $repoRoot $binaryRelativePath
$registryVolume = "leo-vc-roaming-cargo-registry"
$gitVolume = "leo-vc-roaming-cargo-git"
$containerCommand = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build --release --target aarch64-unknown-linux-gnu && file $binaryRelativePath"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI was not found. Install Docker Desktop and start its daemon first."
}
if (-not (Test-Path -LiteralPath $dockerfile)) {
    throw "Dockerfile was not found: $dockerfile"
}

if ($SkipImageBuild) {
    & docker image inspect $ImageTag *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Image '$ImageTag' does not exist. Run without -SkipImageBuild first."
    }
}
else {
    Write-Host "Building cross-compilation image: $ImageTag"
    & docker build --tag $ImageTag --file $dockerfile $repoRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Docker image build failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Building aarch64-unknown-linux-gnu release executable"
$workspaceMount = "$repoRoot`:/workspace"
& docker run --rm `
    --volume $workspaceMount `
    --volume "${registryVolume}:/usr/local/cargo/registry" `
    --volume "${gitVolume}:/usr/local/cargo/git" `
    --workdir /workspace `
    $ImageTag `
    bash -c $containerCommand
if ($LASTEXITCODE -ne 0) {
    throw "Cross-compilation failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path -LiteralPath $binaryPath)) {
    throw "Docker reported success but the binary was not written: $binaryPath"
}

Write-Host "Created: $binaryPath"
