#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-diag-model.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

compiler=${CC:-cc}
common_flags="-std=c11 -Wall -Wextra -Werror -pedantic"

"$compiler" $common_flags "$repo_dir/diag_model.c" "$repo_dir/tests/test_model.c" \
    -o "$build_dir/test_model"
"$build_dir/test_model" "$build_dir/model.json" "$build_dir/model.csv"
python3 -c '
import csv, json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    payload = json.load(source)
assert payload["metadata"]["product"] == "quoted \"product\""
assert payload["metadata"]["version"] == "line\nversion"
assert len(payload["logs"]) == 2
assert payload["logs"][1]["message"] == "comma, quote \" and newline\n"
with open(sys.argv[2], encoding="utf-8", newline="") as source:
    rows = list(csv.reader(source))
assert len(rows) == 3
assert all(len(row) == len(rows[0]) for row in rows)
header = {name: index for index, name in enumerate(rows[0])}
assert rows[1][header["product"]] == "quoted \"product\""
assert rows[2][header["log_message"]] == "comma, quote \" and newline\n"
' "$build_dir/model.json" "$build_dir/model.csv"

if "$compiler" $common_flags -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$repo_dir/diag_model.c" "$repo_dir/tests/test_model.c" -o "$build_dir/test_model_sanitized" \
    >/dev/null 2>&1; then
    "$build_dir/test_model_sanitized"
fi
