#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
firmware_dir=${MOMENTUM_DIR:-"$project_dir/.momentum"}
toolchain_root=${FBT_TOOLCHAIN_PATH:-"$firmware_dir"}
build_dir="$project_dir/.build/ui"
mkdir -p "$build_dir" "$project_dir/docs/captures"
u8g2="$firmware_dir/lib/u8g2"
# Test-only fixtures use the same pinned native PNGs and decoder as the SDK.
# Nothing generated here is linked into the FAP or installer ZIP.
"$toolchain_root/toolchain/current/bin/python3" - "$firmware_dir" "$build_dir" <<'PY'
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(root/'scripts'))
from flipper.assets.icon import file2image
import heatshrink2
assets = {'I_RFIDSmallChip_14x14': 'RFID/RFIDSmallChip_14x14.png',
          'I_Nfc_10px': 'Archive/Nfc_10px.png',
          'I_DolphinWait_59x54': 'Dolphin/DolphinWait_59x54.png',
          'I_DolphinReadingSuccess_59x63': 'Dolphin/DolphinReadingSuccess_59x63.png',
          'I_WarningDolphin_45x42': 'Dolphin/WarningDolphin_45x42.png',
          'I_ButtonLeft_4x7': 'Common/ButtonLeft_4x7.png',
          'I_ButtonCenter_7x7': 'Common/ButtonCenter_7x7.png',
          'I_ButtonRight_4x7': 'Common/ButtonRight_4x7.png'}
header = '#pragma once\n#include <stdint.h>\ntypedef struct {uint16_t width,height; const uint8_t* bitmap;} Icon;\n'
source = '#include "assets_icons.h"\n'
for name, path in assets.items():
    image = file2image(str(root/'assets/icons'/path))
    raw = image.data[1:] if image.data[0] == 0 else heatshrink2.decompress(
        image.data[4:4+int.from_bytes(image.data[2:4], 'little')], window_sz2=8, lookahead_sz2=4)
    assert len(raw) == ((image.width+7)//8)*image.height
    source += f'static const uint8_t {name}_data[] = {{'+','.join(str(byte) for byte in raw)+'};\n'
    source += f'const Icon {name} = {{{image.width},{image.height},{name}_data}};\n'
    header += f'extern const Icon {name};\n'
(output/'assets_icons.h').write_text(header)
(output/'native_icons.c').write_text(source)
(output/'furi_hal_resources.h').write_text('#pragma once\ntypedef enum {LightRed, LightGreen, LightBlue} Light;\n')
# Compile the actual pinned button bodies; the harness only supplies Canvas primitives.
elements = (root/'applications/services/gui/elements.c').read_text()
buttons = '#include <assert.h>\n#include <stddef.h>\n#include <gui/canvas.h>\n#include "assets_icons.h"\n#define furi_check assert\nvoid canvas_draw_icon(Canvas*, int, int, const Icon*);\n'
for position in ('left', 'center', 'right'):
    name = 'elements_button_' + position
    start = elements.index('void ' + name + '(')
    opening = elements.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        if elements[end] == '{': depth += 1
        elif elements[end] == '}': depth -= 1
        end += 1
    buttons += elements[start:end].replace(name, 'native_' + name, 1) + '\n'
(output/'native_buttons.c').write_text(buttons)
(output/'native-assets.txt').write_text('Test-only decoded Momentum native assets; upstream license applies.\n'+'\n'.join(assets.values())+'\n')
PY
linker_flags="-Wl,--gc-sections"
if [ "$(uname -s)" = Darwin ]; then linker_flags="-Wl,-dead_strip"; fi
sanitizer_flags=""
if [ "${DIAG_UI_SANITIZE:-0}" = 1 ]; then
    sanitizer_flags="-fsanitize=address,undefined -fno-omit-frame-pointer"
fi
cc -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -ffunction-sections -fdata-sections \
    -DDIAG_UI_HOST_RENDER -I"$build_dir" -I"$project_dir/tests/host" -I"$u8g2" -I"$firmware_dir/applications/services" \
    "$project_dir/diag_ui.c" "$project_dir/diag_model.c" "$project_dir/diag_feedback.c" "$project_dir/tests/render_ui.c" "$build_dir/native_icons.c" "$build_dir/native_buttons.c" \
    "$u8g2/u8g2_setup.c" "$u8g2/u8g2_font.c" "$u8g2/u8g2_fonts.c" \
    "$u8g2/u8g2_hvline.c" "$u8g2/u8g2_ll_hvline.c" "$u8g2/u8g2_line.c" \
    "$u8g2/u8g2_bitmap.c" "$u8g2/u8x8_8x8.c" "$u8g2/u8g2_box.c" "$u8g2/u8g2_intersection.c" \
    $sanitizer_flags $linker_flags -o "$build_dir/render"
"$build_dir/render" "$project_dir/docs/captures"
