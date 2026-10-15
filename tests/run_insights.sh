#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-diag-insights.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

compiler=${CC:-cc}
common_flags="-std=c11 -Wall -Wextra -Werror -pedantic"

"$compiler" $common_flags \
    "$repo_dir/diag_model.c" "$repo_dir/diag_insights.c" \
    "$repo_dir/tests/test_insights.c" -o "$build_dir/test_insights"
"$build_dir/test_insights"

if "$compiler" $common_flags -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$repo_dir/diag_model.c" "$repo_dir/diag_insights.c" \
    "$repo_dir/tests/test_insights.c" -o "$build_dir/test_insights_sanitized" \
    >/dev/null 2>&1; then
    "$build_dir/test_insights_sanitized"
fi
