#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
firmware_dir=${MOMENTUM_DIR:-"$project_dir/.momentum"}
build_dir="$project_dir/.build/ui"
mkdir -p "$build_dir" "$project_dir/docs/captures"
u8g2="$firmware_dir/lib/u8g2"
linker_flags="-Wl,--gc-sections"
if [ "$(uname -s)" = Darwin ]; then linker_flags="-Wl,-dead_strip"; fi
cc -std=c11 -Wall -Wextra -Wno-unused-parameter -ffunction-sections -fdata-sections \
    -I"$project_dir/tests/host" -I"$u8g2" \
    "$project_dir/diag_ui.c" "$project_dir/diag_capabilities.c" "$project_dir/tests/render_ui.c" \
    "$u8g2/u8g2_setup.c" "$u8g2/u8g2_font.c" "$u8g2/u8g2_fonts.c" \
    "$u8g2/u8g2_hvline.c" "$u8g2/u8g2_ll_hvline.c" "$u8g2/u8g2_line.c" \
    "$u8g2/u8x8_8x8.c" "$u8g2/u8g2_box.c" "$u8g2/u8g2_intersection.c" \
    $linker_flags -o "$build_dir/render"
"$build_dir/render" "$project_dir/docs/captures"
