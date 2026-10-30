#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${1:-.}
FILES=(wg0.netdev wg0.network)

declare -A seen

for file in "${FILES[@]}"; do
    printf '\n=== %s checksums ===\n' "$file"

    while IFS= read -r -d '' host_dir; do
        path="$host_dir/$file"
        [[ -f "$path" ]] || continue

        host=${host_dir##*/}
        hash=$(sha256sum "$path" | awk '{print $1}')

        printf '%-15s  %s\n' "$host" "$hash"
        seen["$file:$hash"]+="$host "
    done < <(
        find "$BASE_DIR" \
            -mindepth 1 -maxdepth 1 \
            -type d -name '10.0.0.*' \
            -print0 |
        sort -zV
    )
done

printf '\n=== Duplicate configurations ===\n'

duplicates=0

for key in "${!seen[@]}"; do
    hosts=${seen[$key]}
    read -r -a host_array <<< "$hosts"

    if (( ${#host_array[@]} > 1 )); then
        file=${key%%:*}
        hash=${key#*:}

        printf '\nDuplicate %s\n' "$file"
        printf 'SHA-256: %s\n' "$hash"
        printf 'Hosts:   %s\n' "$hosts"
        duplicates=1
    fi
done

if (( duplicates == 0 )); then
    printf 'No identical wg0.netdev or wg0.network files found.\n'
fi
