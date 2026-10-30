#!/bin/sh
# Generate systemd-networkd and WSS relay configuration; never install it here.
set -eu
exec python3 "$(dirname "$0")/generate.py" server "$@"
