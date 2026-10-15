#!/bin/sh
set -eu
cd "$(dirname "$0")"
binary=$(mktemp "${TMPDIR:-/tmp}/nfc-reader-tests.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic -DDIAG_READER_TESTING \
    -I.. ../diag_reader.c ../diag_model.c ../diag_insights.c test_reader.c -o "$binary"
"$binary"
cc -std=c11 -Wall -Wextra -Werror -pedantic -DDIAG_READER_TESTING \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I.. ../diag_reader.c ../diag_model.c ../diag_insights.c test_reader.c -o "$binary"
"$binary"
