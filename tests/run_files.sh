#!/bin/sh
set -eu

cd "$(dirname "$0")"

binary=$(mktemp "${TMPDIR:-/tmp}/nfc-diagnostic-suite-test-files.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DDIAG_FILES_HOST -DDIAG_FILES_TESTING \
    -I.. ../diag_files.c ../diag_model.c test_files.c \
    -o "$binary"
"$binary"
