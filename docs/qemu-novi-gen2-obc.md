# QEMU NOVI Gen 2 OBC Experiment

This project measures the VC/BBS+ roaming flow on a QEMU approximation of the
NOVI LLC USA Gen 2 OBC application processor path.

## Simulated Target

- QEMU machine: `virt`
- CPU: `cortex-a72`
- vCPUs: `2`
- RAM: `2048M`
- Guest: Linux AArch64 userspace

This approximates the AMD/Xilinx Versal AI Edge Series dual-core Cortex-A72
application processor path. QEMU does not faithfully emulate the Cortex-R5F,
FPGA fabric, AI Engines, Vorago Cortex-M4 MCU, radiation-hardened FRAM, SEL
immunity, SEU/SEFI mitigation, ECC memory behavior, redundant boot storage, or
actual power draw.

## What Is Simulated

The experimental target remains NOVI LLC USA Gen 2 OBC with AMD/Xilinx Versal
AI Edge Series plus the documented Vorago/radiation-hardened platform
assumptions.

What QEMU actually runs:

- Dual-core Cortex-A72-style AArch64 Linux userspace
- `qemu-system-aarch64`
- `virt` machine
- `cortex-a72`
- `2` vCPUs

What QEMU records as platform assumptions, not faithful emulation:

- Cortex-R5F real-time cores
- Programmable Logic FPGA fabric
- AI Engines
- Vorago Cortex-M4 MCU
- Embedded rad-hard FRAM
- SEL immunity
- SEU/SEFI mitigation
- ECC protected memory interfaces
- Redundant boot images
- Actual `<0.75W` / `5-50W` power behavior

This is the important boundary: our VC/BBS+ experiment is measured on the
closest QEMU-supported Cortex-A72 application processor path. The rest of the
OBC properties are documented in `qemu_profile` and the QEMU config so the
experiment does not pretend QEMU is emulating hardware blocks it cannot model.

## Run

The main entry point is:

```powershell
.\scripts\run-qemu-novi-gen2-obc.ps1
```

On first run it checks for the prepared ARM64 guest disk, cloud-init metadata,
and SSH key. If any of them are missing, it automatically calls
`prepare-qemu-ubuntu-arm64.ps1` to download `noble-server-cloudimg-arm64.img`,
expand it to `20G`, and create the SSH key pair for user `leo`.

You can still run preparation manually when you want to rebuild the guest files:

```powershell
.\scripts\prepare-qemu-ubuntu-arm64.ps1
```

Then SSH in:

```powershell
ssh -i C:\qemu\aarch64\leo-qemu-key leo@localhost -p 2222
```

Inside the guest:

```sh
cd ~/leo-vc-roaming
source ~/.cargo/env
cargo run --release
```

Windows QEMU builds commonly disable `virtfs`, so the runner uses SSH/SCP
instead of 9p folder sharing. After the guest finishes first boot, keep QEMU
running and sync the binary from another PowerShell:

```powershell
.\scripts\sync-binary-to-qemu.ps1
```

If the VM was already booted before SSH keys were added to cloud-init, install
the key once:

```powershell
.\scripts\install-qemu-ssh-key.ps1
```

After that, `sync-binary-to-qemu.ps1` uses `C:\qemu\aarch64\leo-qemu-key` and
does not prompt for the guest password.

## Build

Install an AArch64 Linux Rust target and build the release binary:

```powershell
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

The Windows MSVC toolchain cannot link AArch64 Linux binaries by itself. Use a
Linux/WSL cross toolchain or build inside an AArch64 Linux guest if your host
does not have a compatible linker.

## Legacy Raw Kernel/Rootfs Mode

The previous raw `Image` + `rootfs.raw` path was removed from the main NOVI
runner because it confused the experiment target with a boot mechanism. The
main NOVI runner now boots the prepared Ubuntu ARM64 guest and labels the run
as a NOVI Gen 2 OBC Cortex-A72 approximation.

The experiment writes artifacts and per-stage CPU/RAM/time metrics under
`results/run-*/`.

## Memory Metrics

Memory metrics are enabled without a background sampler. Each stage captures
RSS at start and end only, which avoids the 1 ms sampling thread that previously
perturbed short timing measurements.

- `rss_start_kb`: `VmRSS` at stage start
- `rss_end_kb`: `VmRSS` at stage end
- `rss_stage_delta_kb`: `rss_end_kb - rss_start_kb`
- `process_rss_peak_kb`: Linux `getrusage(RUSAGE_SELF).ru_maxrss`

Use `rss_stage_delta_kb` for low-overhead per-stage memory change. Use
`process_rss_peak_kb` only when you want the historical process-level maximum.

`process_rss_peak_kb` is not a per-stage peak. It is the maximum resident set
size the Linux kernel has observed for the whole process so far. If an earlier
stage already pushed RSS higher, later stages can report the same
`process_rss_peak_kb` even if they did not allocate much memory themselves.
