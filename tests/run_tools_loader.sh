#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-diag-tools-loader.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

compiler=${CC:-cc}
common_flags="-std=c11 -Wall -Wextra -Werror -pedantic -DDIAG_TOOLS_LOADER_TESTING -I$repo_dir"

"$compiler" $common_flags \
    "$repo_dir/diag_tools_loader.c" "$repo_dir/tests/test_tools_loader.c" \
    -o "$build_dir/test_tools_loader"
"$build_dir/test_tools_loader"

if "$compiler" $common_flags -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$repo_dir/diag_tools_loader.c" "$repo_dir/tests/test_tools_loader.c" \
    -o "$build_dir/test_tools_loader_sanitized" >/dev/null 2>&1; then
    "$build_dir/test_tools_loader_sanitized"
fi
