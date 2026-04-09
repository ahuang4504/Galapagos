#!/bin/sh
set -e

CONFIG="${UNBOUND_CONFIG:-weak}"
echo "Starting Unbound with config: unbound-${CONFIG}.conf"

cp "/etc/unbound/unbound-${CONFIG}.conf" /etc/unbound/unbound.conf

# Ensure the dnstap socket directory is owned by the unbound user
chown -R unbound:unbound /var/run/unbound

exec unbound -d -v -c /etc/unbound/unbound.conf
