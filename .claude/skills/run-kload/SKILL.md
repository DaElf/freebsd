---
name: run-kload
description: build, install, and test the kload kernel-live-reload feature; run kload binary; smoke test kload on FreeBSD; build KERNCONF=KLOAD kernel
---

# kload — FreeBSD kernel live-load feature

kload is a FreeBSD kernel feature (amd64 only) that lets a running
kernel load and jump to a new kernel image without going through the
firmware.  It consists of a kernel component (built with
`KERNCONF=KLOAD`) and a userland binary (`/usr/sbin/kload`).

**Build and run require a FreeBSD host.** This repo is developed on
Linux; edits are made there but all builds and execution happen on a
FreeBSD machine.

The driver is `.claude/skills/run-kload/smoke.sh` — three sub-commands:
`build`, `install`, `check`.

---

## Key files

| Path | What it is |
|------|-----------|
| `sys/kern/kern_kload.c` | Core kload syscall + prealloc + indirection pages |
| `sys/amd64/amd64/kload.c` | amd64 page-table builder |
| `sys/amd64/amd64/kload_exec.S` | relocate_kernel trampoline (runs from control page) |
| `sys/x86/x86/mp_x86.c` | `cpukload_handler`, `kload_suspend_cpus` |
| `sys/amd64/amd64/apic_vector.S` | IPI_KLOAD entry stub |
| `usr.sbin/kload/kload.c` | Userland loader (userboot-based) |
| `usr.sbin/kload/Makefile` | Userland build |
| `sys/conf/files.amd64` | Wires kload*.c + kload_exec.S into kernel build |
| `sys/conf/options.amd64` | Defines `KLOAD` option → `opt_kload.h` |

---

## Run (agent path) — smoke.sh

Run on a FreeBSD build/test host from the repo root:

```sh
# Build kernel and userland
sh .claude/skills/run-kload/smoke.sh build

# Install (requires sudo)
sh .claude/skills/run-kload/smoke.sh install

# Verify after booting the KLOAD kernel
sh .claude/skills/run-kload/smoke.sh check
```

---

## Build (manual)

```sh
# Kernel — outputs to /boot/KLOAD/kernel after install
make -j$(sysctl -n hw.ncpu) KERNCONF=KLOAD buildkernel 2>&1 | tee k.out

# Userland binary
make -C usr.sbin/kload

# Install both
sudo make KERNCONF=KLOAD installkernel
sudo make -C usr.sbin/kload install
```

---

## Boot the KLOAD kernel

```sh
# One-shot next boot
nextboot -k KLOAD

# Or at loader prompt:
load /boot/KLOAD/kernel
boot

# Or persistently in /boot/loader.conf:
kernel="KLOAD"
```

---

## Run kload

After booting the KLOAD kernel, load a new kernel image:

```sh
# Minimal — uses /boot/KLOAD/kernel as the new image
sudo kload /path/to/new/kernel

# With explicit loader
sudo kload -l /boot/userboot.so /path/to/new/kernel

# Stdio console
sudo kload -c stdio /path/to/new/kernel
```

---

## Upgrade base system (FreeBSD 16 pkgbase)

The target machine uses pkgbase (package-managed base). Do not use
`installworld` directly — it conflicts with the package database.

```sh
# Build pkgbase packages after buildworld
make packages

# Point pkg at the local repo (create /usr/local/etc/pkg/repos/local.conf):
# local: { url: "file:///usr/obj/.../repo/FreeBSD:16:amd64/latest", enabled: yes, priority: 100 }

# Merge /etc changes first
sudo etcupdate -s /path/to/freebsd/src

# Upgrade base via pkg
sudo pkg upgrade

# Kernel is separate — not managed by pkg
sudo make KERNCONF=KLOAD installkernel
```

---

## Branch layout

Working branch: `kload-fbsd16` (FreeBSD 16 base + kload cherry-picked
from `origin/kload-cur12-split` with FreeBSD 12→16 API fixes).

Key API changes resolved during the port:
- `kmem_alloc_attr` / `kmem_free` / `kmem_malloc` lost `kernel_arena`
  first arg; return type changed to `void *` (cast to `vm_offset_t`)
- `CPU_NAND` → `CPU_ANDNOT` (3-arg form)
- `apic_ops` dispatch removed; functions called directly
- `IDTVEC` + `PUSH_FRAME` → `INTR_HANDLER` macro
- `assym.s` → `assym.inc`
- `struct sysent` field order changed; use designated initializers
- `userboot.h` `.stat` callback now takes `struct stat *`; `.getenv` returns `char *`

---

## Gotchas

- **Linux dev machine**: edits work, but `make buildkernel` requires FreeBSD
  bmake and the FreeBSD clang toolchain. Do not use GNU make directly.
- **pkgbase conflict**: `sudo make installworld` fails on a pkgbase system.
  Use `make packages` + `pkg upgrade` for base, `installkernel` for kernel.
- **kgmon removed**: `usr.sbin/Makefile.amd64` must not include `kgmon`
  (directory absent in FreeBSD 16).
- **IPI slot**: `IPI_KLOAD` sits at `APIC_IPI_INTS + 10`; shifting it
  changes `IPI_DYN_FIRST` and could conflict with other IPI users.
- **relocate_kernel runs from its own page**: code and stack both live
  in the control page — do not add large stack allocations there.
- **CR4 before CR3**: Intel SDM requires CR4.PAE set before loading a PAE
  page table. The trampoline now sets CR4 first (fixed in this branch).
