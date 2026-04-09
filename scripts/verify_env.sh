#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== DNShield Environment Verification ==="

echo ""
echo "[1/6] Checking all containers are running..."
docker compose ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"

echo ""
echo "[2/6] Checking Unbound dnstap support..."
docker compose exec resolver unbound -V 2>&1 | grep -i dnstap \
    && echo "  dnstap: SUPPORTED" \
    || echo "  WARNING: dnstap not in this Unbound build — using text log fallback"

echo ""
echo "[3/6] Testing resolver from client (dig @172.28.0.10 google.com)..."
RESULT=$(docker compose exec client dig +short @172.28.0.10 google.com | head -1)
if [ -n "$RESULT" ]; then
    echo "  Resolution OK: $RESULT"
else
    echo "  FAIL: no answer from resolver"
    exit 1
fi

echo ""
echo "[4/6] Testing resolver from attacker container..."
RESULT=$(docker compose exec attacker dig +short @172.28.0.10 example.com | head -1)
if [ -n "$RESULT" ]; then
    echo "  Resolution OK: $RESULT"
else
    echo "  FAIL: no answer from resolver"
    exit 1
fi

echo ""
echo "[5/6] Verifying attacker has raw socket capability (scapy)..."
docker compose exec attacker python3 -c "from scapy.all import conf; print('  scapy OK, iface:', conf.iface)"

echo ""
echo "[6/6] Verifying network connectivity (all containers can reach resolver)..."
for svc in client attacker detector; do
    docker compose exec "$svc" ping -c1 -W2 172.28.0.10 > /dev/null 2>&1 \
        && echo "  $svc -> resolver: OK" \
        || echo "  $svc -> resolver: FAIL"
done

echo ""
echo "=== Verification complete ==="
