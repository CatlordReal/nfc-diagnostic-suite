#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
firmware_dir=${MOMENTUM_DIR:-"$project_dir/.momentum"}
revision=${1:-e1784e7418d8b074e971983ceb6fef0f37e52ae4}
if [ ! -e "$firmware_dir/.git" ]; then
    if [ -e "$firmware_dir" ]; then
        printf '%s\n' 'Destination exists and is not a Git checkout; refusing replacement.' >&2
        exit 1
    fi
    git clone --no-checkout https://github.com/Next-Flip/Momentum-Firmware.git "$firmware_dir"
    git -C "$firmware_dir" checkout --detach "$revision"
else
    current_revision=$(git -C "$firmware_dir" rev-parse HEAD)
    if [ "$current_revision" != "$revision" ]; then
        printf '%s\n' 'Existing checkout has another revision; use it via MOMENTUM_DIR or choose a fresh destination.' >&2
        exit 1
    fi
fi
git -C "$firmware_dir" submodule update --init --recursive --jobs 4
printf 'Momentum source ready: %s\n' "$firmware_dir"
