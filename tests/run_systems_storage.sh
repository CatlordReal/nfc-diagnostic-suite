#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
firmware_dir=${MOMENTUM_DIR:-"$repo_dir/.momentum"}
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-systems-storage-tests.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
for sanitizer in no yes; do
    flags=""
    if [ "$sanitizer" = yes ]; then flags="-fsanitize=address,undefined -fno-omit-frame-pointer"; fi
    cc -std=c11 -Wall -Wextra -Werror -pedantic $flags \
        -DDIAG_SYSTEMS_STORAGE_TESTING \
        -I"$firmware_dir/applications/services/storage" \
        "$repo_dir/diag_systems.c" "$repo_dir/diag_insights.c" "$repo_dir/tests/test_systems_storage.c" \
        -o "$build_dir/test"
    "$build_dir/test"
done
