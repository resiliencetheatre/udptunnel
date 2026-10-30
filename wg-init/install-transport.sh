#!/bin/sh
# Install this generated bundle. Pass --start to activate the generated services.
set -eu
case "${1:-}" in ''|--start) ;; *) echo 'Usage: sudo ./install.sh [--start]' >&2; exit 1 ;; esac
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
[ -x @BINARY@ ] || { echo 'Install wstunnel at @BINARY@ first.' >&2; exit 1; }
getent group systemd-network >/dev/null
# systemd-networkd must be able to read the private key, but other users must not.
install -d -m 0755 /etc/systemd/network
install -o root -g systemd-network -m 0640 @IFACE@.netdev /etc/systemd/network/@IFACE@.netdev
install -o root -g root -m 0644 @IFACE@.network /etc/systemd/network/@IFACE@.network
install -o root -g root -m 0600 wstunnel-mesh.service /etc/systemd/system/wstunnel-mesh.service
@EXTRA_INSTALL@
systemctl daemon-reload
systemctl enable systemd-networkd.service wstunnel-mesh.service
if [ "${1:-}" = --start ]; then
    systemctl start systemd-networkd.service
    networkctl reload
    # reload creates @IFACE@ if absent; the kernel device may appear asynchronously.
    n=0
    until ip link show @IFACE@ >/dev/null 2>&1; do
        n=$((n+1)); [ "$n" -lt 30 ] || { echo '@IFACE@ did not appear' >&2; exit 1; }; sleep 1
    done
    networkctl reconfigure @IFACE@
    systemctl restart wstunnel-mesh.service
@EXTRA_START@
fi
echo 'Installed. See README.txt for routing/firewall requirements and verification.'
