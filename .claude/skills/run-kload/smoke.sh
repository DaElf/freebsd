#!/bin/sh
# smoke.sh — build and basic-verify the kload kernel + userland
# Run this on a FreeBSD build host from the repo root.
# Usage: sh .claude/skills/run-kload/smoke.sh [build|install|check]
set -e

KERNCONF=KLOAD
OBJDIR=${OBJDIR:-$(pwd)/../obj}
NCPU=$(sysctl -n hw.ncpu 2>/dev/null || nproc)

die() { echo "FAIL: $*" >&2; exit 1; }
ok()  { echo "OK:   $*"; }

cmd=${1:-build}

case "$cmd" in
build)
    echo "==> Building kernel KERNCONF=$KERNCONF"
    make -j"$NCPU" KERNCONF=$KERNCONF OBJDIR="$OBJDIR" buildkernel 2>&1 | tee /tmp/kload_kernel.out
    grep -q "^make\[1\]: .* done" /tmp/kload_kernel.out || \
        grep -q "^---" /tmp/kload_kernel.out && ok "kernel build" || die "kernel build failed — see /tmp/kload_kernel.out"

    echo "==> Building userland kload binary"
    make -C usr.sbin/kload 2>&1 | tee /tmp/kload_user.out
    ok "userland build"
    ;;

install)
    echo "==> Installing kernel"
    sudo make KERNCONF=$KERNCONF OBJDIR="$OBJDIR" installkernel
    ok "kernel installed to /boot/$KERNCONF"

    echo "==> Installing userland binary"
    sudo make -C usr.sbin/kload install
    ok "kload binary installed"
    ;;

check)
    # Run on the target machine after booting the KLOAD kernel.
    echo "==> Checking kload kernel module is available"
    kldstat | grep -q kload && ok "kload kld loaded" || \
        kldload kload && ok "kload kld loaded (just loaded)" || die "kload kld not found"

    echo "==> Checking kload device node"
    [ -c /dev/kload ] && ok "/dev/kload exists" || die "/dev/kload missing"

    echo "==> Checking kload binary"
    which kload >/dev/null 2>&1 && ok "kload binary in PATH" || die "kload not in PATH"
    kload --help 2>&1 | grep -q "usage\|Usage\|kload" && ok "kload --help responded" || true

    echo "==> All checks passed"
    ;;

*)
    echo "Usage: $0 [build|install|check]" >&2
    exit 1
    ;;
esac
