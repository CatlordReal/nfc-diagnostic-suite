#!/bin/sh
set -eu

cd "$(dirname "$0")"

binary=$(mktemp "${TMPDIR:-/tmp}/nfc-diagnostic-suite-test-workflow.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DDIAG_WORKFLOW_HOST -DDIAG_WORKFLOW_TESTING \
    -I.. ../diag_workflow.c test_workflow.c \
    -o "$binary"
"$binary"
