#!/bin/sh
set -eu

cd "$(dirname "$0")"

binary=$(mktemp "${TMPDIR:-/tmp}/nfc-diagnostic-suite-test-capabilities.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I.. ../diag_model.c ../diag_capabilities.c test_capabilities.c \
    -o "$binary"
"$binary"
