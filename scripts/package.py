#!/usr/bin/env python3
"""Package the standalone installer bundle."""
from pathlib import Path
import hashlib
import zipfile

root = Path(__file__).resolve().parent.parent
dist = root / 'dist'
output = dist / 'nfc-diagnostic-suite-v2.0.1.zip'
artifact = dist / 'nfc_diagnostic_suite.fap'
build_record = dist / 'BUILD.txt'
required = [artifact, root / 'README.md', root / 'LICENSE',
            root / 'nfc_diagnostic_icon.png', build_record]
missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
if missing:
    raise SystemExit('Missing release inputs: ' + ', '.join(missing))
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in required:
        archive.write(path, Path('nfc-diagnostic-suite') / path.relative_to(root))
with zipfile.ZipFile(output) as archive:
    if archive.testzip() is not None:
        raise SystemExit('ZIP integrity failed')
    names = set(archive.namelist())
    if any('nfc-diagnostic-suite/' + str(path.relative_to(root)) not in names for path in required):
        raise SystemExit('ZIP missing required input')
    expected = {'nfc-diagnostic-suite/' + str(path.relative_to(root)) for path in required}
    if names != expected:
        raise SystemExit('ZIP contains unexpected files')
checksums = [output, artifact]
(dist / 'SHA256SUMS.txt').write_text(''.join(
    f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(dist)}\n'
    for path in checksums))
print(f'{output}: {output.stat().st_size:,} bytes; standalone installer ZIP passed')
