#!/bin/sh
set -eu

cd "$(dirname "$0")"

binary=$(mktemp "${TMPDIR:-/tmp}/nfc-diagnostic-suite-test-systems.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DDIAG_SYSTEMS_HOST -DDIAG_SYSTEMS_TESTING \
    -I.. ../diag_systems.c ../diag_insights.c test_systems.c \
    -o "$binary"
"$binary"
