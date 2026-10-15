#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-diag-engine.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

compiler=${CC:-cc}
common_flags="-std=c11 -Wall -Wextra -Werror -pedantic -DDIAG_NFC_TESTING"

"$compiler" $common_flags "$repo_dir/diag_model.c" "$repo_dir/diag_nfc.c" \
    "$repo_dir/tests/test_nfc.c" -o "$build_dir/test_nfc"
"$build_dir/test_nfc"

# Firmware ARM ABI uses short enums; repeat evidence tests with that layout.
"$compiler" $common_flags -fshort-enums "$repo_dir/diag_model.c" "$repo_dir/diag_nfc.c" \
    "$repo_dir/tests/test_nfc.c" -o "$build_dir/test_nfc_short_enums"
"$build_dir/test_nfc_short_enums"

if "$compiler" $common_flags -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$repo_dir/diag_model.c" "$repo_dir/diag_nfc.c" "$repo_dir/tests/test_nfc.c" \
    -o "$build_dir/test_nfc_sanitized" >/dev/null 2>&1; then
    "$build_dir/test_nfc_sanitized"
fi
