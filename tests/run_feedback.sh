#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
firmware_dir=${MOMENTUM_DIR:-"$project_dir/.momentum-mntm012"}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfc-feedback-tests.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
# Compile the pinned SDK's actual NotificationMessage/Sequence types.
printf '%s\n' '#pragma once' 'typedef enum {LightRed, LightGreen, LightBlue} Light;' > "$work_dir/furi_hal_resources.h"
for sanitizer in no yes; do
    flags=""
    if [ "$sanitizer" = yes ]; then flags="-fsanitize=address,undefined -fno-omit-frame-pointer"; fi
    cc -std=c11 -Wall -Wextra -Werror -pedantic $flags \
        -I"$work_dir" -I"$firmware_dir/applications/services" \
        "$project_dir/diag_feedback.c" "$project_dir/tests/test_feedback.c" \
        -o "$work_dir/test"
    "$work_dir/test"
done
