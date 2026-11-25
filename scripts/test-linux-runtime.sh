#!/usr/bin/env bash
# Privileged Linux runtime smoke tests.
#
# WARNING: this attaches real eBPF programs. Run on a disposable VM/netns,
# not on a production host. It uses lo for XDP and does not modify cgroups.
#
# Usage:
#   sudo -E AYA_APP=./target/release/aya-app bash scripts/test-linux-runtime.sh
#
# Exit code is non-zero if a required kernel feature is absent or a required
# scenario fails. Optional scenarios (fentry/LSM) are skipped when unsupported.
set -euo pipefail

cd "$(dirname "$0")/.."
APP="${AYA_APP:-./target/release/aya-app}"

if [[ "$(id -u)" != "0" ]]; then
    echo "run as root (sudo -E)" >&2
    exit 1
fi
if [[ ! -x "$APP" ]]; then
    echo "missing executable: $APP (set AYA_APP)" >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'killall aya-app 2>/dev/null || true; rm -rf "$TMP"' EXIT HUP INT TERM

pass=0
fail=0
skip=0

ok()   { echo "PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $*"; fail=$((fail + 1)); }
skip() { echo "SKIP  $*"; skip=$((skip + 1)); }

echo "==> system"
cat /etc/os-release | sed -n '1,4p'
uname -a
[[ -e /sys/kernel/btf/vmlinux ]] && echo "BTF: yes" || { echo "BTF: no"; exit 1; }

echo "==> XDP lo"
timeout 6 "$APP" xdp --iface lo --mode skb --block-icmp \
    --protected-ip 127.0.0.1 --protected-prefix-len 32 \
    --stats-interval 2 >"$TMP/xdp" 2>&1 &
sleep 2
ping -c 2 127.0.0.1 >/dev/null 2>&1 || true
sleep 4
if grep -q 'drop : icmp=' "$TMP/xdp"; then ok "XDP ICMP drop"; else bad "XDP (see $TMP/xdp)"; cat "$TMP/xdp"; fi
killall aya-app 2>/dev/null || true

echo "==> kprobe"
timeout 5 "$APP" kprobe --path-prefix /etc/shadow \
    --latency-threshold-us 0 --stats-interval 2 >"$TMP/kprobe" 2>&1 &
sleep 2
cat /etc/shadow >/dev/null
sleep 3
if grep -q 'opens ' "$TMP/kprobe"; then ok "kprobe openat"; else bad "kprobe (see $TMP/kprobe)"; cat "$TMP/kprobe"; fi
killall aya-app 2>/dev/null || true

echo "==> raw tracepoint"
timeout 5 "$APP" raw-tp --syscall-nr 2 --event-sample 1 \
    --stats-interval 2 >"$TMP/rawtp" 2>&1 &
sleep 2
cat /etc/hosts >/dev/null
sleep 3
if grep -q 'matches ' "$TMP/rawtp"; then ok "raw tracepoint"; else bad "raw tracepoint (see $TMP/rawtp)"; cat "$TMP/rawtp"; fi
killall aya-app 2>/dev/null || true

if grep -qw function /sys/kernel/tracing/available_tracers 2>/dev/null; then
    echo "==> fentry"
    timeout 5 "$APP" fentry --symbol do_sys_openat2 \
        --latency-threshold-us 0 --stats-interval 2 >"$TMP/fentry" 2>&1 &
    sleep 2
    cat /etc/hosts >/dev/null
    sleep 3
    if grep -q 'enters ' "$TMP/fentry"; then ok "fentry"; else bad "fentry (see $TMP/fentry)"; cat "$TMP/fentry"; fi
    killall aya-app 2>/dev/null || true
else
    skip "fentry: function tracer unavailable"
fi

if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "==> LSM"
    timeout 5 "$APP" lsm --block-port 18081 --uid 0 \
        --event-sample 1 --stats-interval 2 >"$TMP/lsm" 2>&1 &
    sleep 2
    timeout 2 nc 127.0.0.1 18081 </dev/null >/dev/null 2>&1 || true
    sleep 3
    if grep -q 'denied:' "$TMP/lsm"; then ok "LSM"; else bad "LSM (see $TMP/lsm)"; cat "$TMP/lsm"; fi
    killall aya-app 2>/dev/null || true
else
    skip "LSM: bpf LSM not enabled"
fi

echo
echo "runtime smoke: pass=$pass fail=$fail skip=$skip"
[[ "$fail" -eq 0 ]]
