#!/bin/sh
set -e

CONFIG="${UNBOUND_CONFIG:-weak}"
echo "Starting Unbound with config: unbound-${CONFIG}.conf"

cp "/etc/unbound/unbound-${CONFIG}.conf" /etc/unbound/unbound.conf

exec unbound -d -v -c /etc/unbound/unbound.conf
