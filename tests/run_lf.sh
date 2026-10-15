#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-diag-lf.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

compiler=${CC:-cc}
common_flags="-std=c11 -Wall -Wextra -Werror -pedantic -DDIAG_LF_TESTING"

"$compiler" $common_flags \
    "$repo_dir/diag_model.c" "$repo_dir/diag_lf.c" "$repo_dir/tests/test_lf.c" \
    -o "$build_dir/test_lf"
"$build_dir/test_lf"

if "$compiler" $common_flags -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$repo_dir/diag_model.c" "$repo_dir/diag_lf.c" "$repo_dir/tests/test_lf.c" \
    -o "$build_dir/test_lf_sanitized" >/dev/null 2>&1; then
    "$build_dir/test_lf_sanitized"
fi
