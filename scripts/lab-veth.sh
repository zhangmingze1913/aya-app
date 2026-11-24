#!/usr/bin/env bash
# Create an isolated netns/veth pair for XDP/TC experiments.
#
# Usage:
#   bash scripts/lab-veth.sh up
#   bash scripts/lab-veth.sh down
#
# The host side is veth-host (10.20.0.1/24); the peer is veth-lab inside the
# aya-lab netns (10.20.0.2/24). Attach XDP/TC to veth-host.
set -euo pipefail

NS=aya-lab
HOST_IF=veth-host
LAB_IF=veth-lab
HOST_IP=10.20.0.1/24
LAB_IP=10.20.0.2/24

up() {
    if ip netns list | grep -qw "$NS"; then
        echo "netns $NS already exists; run '$0 down' first" >&2
        exit 1
    fi

    ip netns add "$NS"
    ip link add "$HOST_IF" type veth peer name "$LAB_IF"
    ip link set "$LAB_IF" netns "$NS"

    ip addr add "$HOST_IP" dev "$HOST_IF"
    ip link set "$HOST_IF" up

    ip netns exec "$NS" ip addr add "$LAB_IP" dev "$LAB_IF"
    ip netns exec "$NS" ip link set "$LAB_IF" up
    ip netns exec "$NS" ip link set lo up

    echo "ready: host=$HOST_IF ($HOST_IP), lab=$NS/$LAB_IF ($LAB_IP)"
    echo "test:  ip netns exec $NS ping -c 1 ${HOST_IP%/*}"
}

down() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    echo "cleaned up $NS / $HOST_IF"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *)
        echo "usage: $0 up|down" >&2
        exit 1
        ;;
esac
