#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$project_dir/tests/run.sh"
"$project_dir/tests/run_files.sh"
"$project_dir/tests/run_nfc.sh"
"$project_dir/tests/run_lf.sh"
"$project_dir/tests/run_reader.sh"
"$project_dir/tests/run_workflow.sh"
"$project_dir/tests/run_capabilities.sh"
"$project_dir/tests/render_ui.sh"
printf '%s\n' 'Host checks passed. Physical NFC/LF, reader interaction, SD, USB, handoffs and XP remain hardware acceptance checks.'
