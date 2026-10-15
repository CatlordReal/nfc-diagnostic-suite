#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-navigation.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=address,undefined \
    -I"$project_dir" "$project_dir/tests/test_navigation.c" -o "$build_dir/test_navigation"
"$build_dir/test_navigation"
cc -std=c11 -Wall -Wextra -Werror -pedantic -fshort-enums -fsanitize=address,undefined \
    -I"$project_dir" "$project_dir/tests/test_navigation.c" -o "$build_dir/test_navigation_short_enums"
"$build_dir/test_navigation_short_enums"
