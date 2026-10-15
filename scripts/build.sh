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
./fbt fap_nfc_diagnostic_suite fap_mfkey fap_nfc_magic fap_picopass
# FBT's normal firmware configuration emits these four targets together.
artifact_dir="$firmware_dir/build/f7-firmware-C/.extapps"
mkdir -p "$project_dir/dist/apps/NFC"
for app in nfc_diagnostic_suite mfkey nfc_magic picopass; do
    artifact="$artifact_dir/$app.fap"
    if [ ! -f "$artifact" ]; then
        printf '%s\n' "Missing FBT artifact: $artifact" >&2
        exit 1
    fi
    case "$app" in
        nfc_diagnostic_suite)
            python3 "$project_dir/scripts/check-imports.py" "$firmware_dir" "$artifact" \
                --icon "$project_dir/nfc_diagnostic_icon.png" ;;
        mfkey)
            python3 "$project_dir/scripts/check-imports.py" "$firmware_dir" "$artifact" \
                --profile companion --icon "$firmware_dir/applications/external/mfkey/mfkey.png" \
                --require-embedded-plugin mfkey_init_plugin.fal ;;
        nfc_magic)
            python3 "$project_dir/scripts/check-imports.py" "$firmware_dir" "$artifact" \
                --profile companion --icon "$firmware_dir/applications/external/nfc_magic/assets/125_10px.png" ;;
        picopass)
            python3 "$project_dir/scripts/check-imports.py" "$firmware_dir" "$artifact" \
                --profile companion --icon "$firmware_dir/applications/external/picopass/125_10px.png" ;;
    esac
    cp "$artifact" "$project_dir/dist/apps/NFC/$app.fap"
done
cp "$project_dir/dist/apps/NFC/nfc_diagnostic_suite.fap" "$project_dir/dist/nfc_diagnostic_suite.fap"
# Retain source icons, manifests, upstream descriptions, and the upstream license.
mkdir -p "$project_dir/dist/vendor"
cp "$firmware_dir/LICENSE" "$project_dir/dist/vendor/Momentum-LICENSE"
for app in mfkey nfc_magic picopass; do
    vendor="$project_dir/dist/vendor/$app"
    source="$firmware_dir/applications/external/$app"
    mkdir -p "$vendor"
    cp "$source/application.fam" "$vendor/application.fam"
    if [ -f "$source/.catalog/README.md" ]; then
        cp "$source/.catalog/README.md" "$vendor/UPSTREAM-README.md"
    fi
    case "$app" in
        mfkey) cp "$source/mfkey.png" "$vendor/mfkey.png" ;;
        nfc_magic) cp "$source/assets/125_10px.png" "$vendor/125_10px.png" ;;
        picopass)
            cp "$source/125_10px.png" "$vendor/125_10px.png"
            cp "$source/lib/asn1/asn_system.h" "$vendor/ASN1-NOTICE.h"
            cp "$project_dir/scripts/licenses/asn1c-LICENSE.txt" "$vendor/ASN1-LICENSE.txt"
            cp "$source/bsearch.c" "$vendor/BSEARCH-NOTICE.c"
            cp "$firmware_dir/lib/mbedtls/LICENSE" "$vendor/MBEDTLS-LICENSE"
            # Preserve the loclass license notice and contributor attribution.
            sed -n '1,/^#include/p' "$source/lib/loclass/optimized_cipher.c" > "$vendor/LOCLASS-NOTICE.txt" ;;
    esac
done
apps_revision=$(git -C "$firmware_dir/applications/external" rev-parse HEAD)
cat > "$project_dir/dist/vendor/SOURCE.txt" <<EOF
Native companions built without algorithm changes from Momentum Firmware.
Repository: https://github.com/Next-Flip/Momentum-Firmware
Commit: $revision
Source archive: https://github.com/Next-Flip/Momentum-Firmware/archive/$revision.tar.gz
Momentum-Apps submodule: https://github.com/Next-Flip/Momentum-Apps
Momentum-Apps commit: $apps_revision
Momentum-Apps source archive: https://github.com/Next-Flip/Momentum-Apps/archive/$apps_revision.tar.gz
MFKey: https://github.com/Next-Flip/Momentum-Apps/tree/$apps_revision/mfkey
NFC Magic: https://github.com/Next-Flip/Momentum-Apps/tree/$apps_revision/nfc_magic
HID iClass (PicoPass): https://github.com/Next-Flip/Momentum-Apps/tree/$apps_revision/picopass
ASN.1 license: https://github.com/vlm/asn1c/blob/8a274c3f99761f249b6c205e1c89be1b1cb7c669/LICENSE
PicoPass BSD notices: BSEARCH-NOTICE.c, ASN1-NOTICE.h and ASN1-LICENSE.txt.
PicoPass Mbed TLS license: MBEDTLS-LICENSE (unmodified pinned submodule text).
The retained Momentum-LICENSE and component notices accompany the binaries.
Fetch complete corresponding source and its submodules using scripts/setup-momentum.sh.
EOF
printf 'Momentum source: %s\n' "$revision" > "$project_dir/dist/BUILD.txt"
printf 'Momentum-Apps source: %s\n' "$apps_revision" >> "$project_dir/dist/BUILD.txt"
rg '^Version,' targets/f7/api_symbols.csv >> "$project_dir/dist/BUILD.txt"
cd "$project_dir/dist"
shasum -a 256 nfc_diagnostic_suite.fap apps/NFC/*.fap >> BUILD.txt
printf '%s\n' "Built diagnostics and three native companions in $project_dir/dist/apps/NFC"
