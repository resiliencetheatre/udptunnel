#!/bin/sh
# create-client.sh 10.1.0.2 [--output peer-1 --server-dir relay ...]
set -eu
exec python3 "$(dirname "$0")/generate.py" client "$@"
