#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
firmware_dir=${MOMENTUM_DIR:-"$project_dir/.momentum"}
if [ ! -f "$firmware_dir/fbt" ]; then
    printf '%s\n' 'Set MOMENTUM_DIR to your checked-out Momentum firmware source tree.' >&2
    exit 1
fi
firmware_dir=$(CDPATH= cd -- "$firmware_dir" && pwd)
if ! git -C "$firmware_dir" remote -v | rg -q 'Next-Flip/Momentum-Firmware'; then
    printf '%s\n' 'Expected a Momentum-Firmware source checkout.' >&2
    exit 1
fi
revision=$(git -C "$firmware_dir" rev-parse HEAD)
printf '#pragma once\n#define DIAG_FIRMWARE_BUILD "%s"\n' "$revision" > "$project_dir/diag_build.h"
app_path="$firmware_dir/applications_user/nfc_diagnostic_suite"
created_app_link=false
if [ -e "$app_path" ] || [ -L "$app_path" ]; then
    if [ "$(readlink "$app_path" 2>/dev/null || true)" != "$project_dir" ]; then
        printf '%s\n' "Refusing to replace existing $app_path" >&2
        exit 1
    fi
else
    ln -s "$project_dir" "$app_path"
    created_app_link=true
fi
cleanup_app_link() {
    if [ "$created_app_link" = true ] && [ -L "$app_path" ] && \
       [ "$(readlink "$app_path")" = "$project_dir" ]; then
        rm -- "$app_path"
    fi
}
trap cleanup_app_link EXIT
trap 'exit 1' HUP INT TERM
cd "$firmware_dir"
./fbt fap_nfc_diagnostic_suite "$@"
artifact_dir="$firmware_dir/build/f7-firmware-C/.extapps"
artifact="$artifact_dir/nfc_diagnostic_suite.fap"
if [ ! -f "$artifact" ]; then
    printf '%s\n' "Missing FBT artifact: $artifact" >&2
    exit 1
fi
python3 "$project_dir/scripts/check-imports.py" "$firmware_dir" "$artifact" \
    --icon "$project_dir/nfc_diagnostic_icon.png"
mkdir -p "$project_dir/dist"
cp "$artifact" "$project_dir/dist/nfc_diagnostic_suite.fap"
printf 'Momentum source: %s\n' "$revision" > "$project_dir/dist/BUILD.txt"
rg '^Version,' targets/f7/api_symbols.csv >> "$project_dir/dist/BUILD.txt"
cd "$project_dir/dist"
shasum -a 256 nfc_diagnostic_suite.fap >> BUILD.txt
printf '%s\n' "Built $project_dir/dist/nfc_diagnostic_suite.fap"
