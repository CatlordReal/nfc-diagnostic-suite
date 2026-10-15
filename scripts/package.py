#!/usr/bin/env python3
"""Package the standalone source and verified native companion distribution."""
from pathlib import Path
import hashlib
import zipfile

root = Path(__file__).resolve().parent.parent
dist = root / 'dist'
output = dist / 'nfc-diagnostic-suite-v2.0.zip'
apps = ('nfc_diagnostic_suite', 'mfkey', 'nfc_magic', 'picopass')
required = [root / name for name in (
    'application.fam', 'README.md', 'LICENSE', 'AGENTS.md', '.gitignore', 'nfc_diagnostic_icon.png',
    'diag_nfc.c', 'diag_reader.c', 'diag_lf.c', 'diag_capabilities.c',
    'scripts/setup-momentum.sh', 'scripts/build.sh', 'scripts/check-imports.py',
    'scripts/test.sh', 'docs/ENGINEERING.md', 'dist/BUILD.txt',
    'dist/nfc_diagnostic_suite.fap', 'dist/vendor/SOURCE.txt',
    'dist/vendor/Momentum-LICENSE', 'dist/vendor/mfkey/mfkey.png',
    'dist/vendor/nfc_magic/125_10px.png', 'dist/vendor/picopass/125_10px.png',
    'dist/vendor/picopass/ASN1-NOTICE.h', 'dist/vendor/picopass/ASN1-LICENSE.txt',
    'dist/vendor/picopass/BSEARCH-NOTICE.c', 'dist/vendor/picopass/MBEDTLS-LICENSE',
    'dist/vendor/picopass/LOCLASS-NOTICE.txt')]
for app in ('mfkey', 'nfc_magic', 'picopass'):
    required.extend(dist / 'vendor' / app / name
                    for name in ('application.fam', 'UPSTREAM-README.md'))
required.extend(dist / 'apps/NFC' / (app + '.fap') for app in apps)
missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
if missing:
    raise SystemExit('Missing release inputs: ' + ', '.join(missing))
if (dist / 'nfc_diagnostic_suite.fap').read_bytes() != (dist / 'apps/NFC/nfc_diagnostic_suite.fap').read_bytes():
    raise SystemExit('Primary FAP copies differ; rebuild before packaging')
files = [*root.glob('*.c'), *root.glob('*.h'), root / 'application.fam',
         root / 'README.md', root / 'LICENSE', root / 'AGENTS.md', root / '.gitignore', root / 'nfc_diagnostic_icon.png']
for directory in ('scripts', 'tests', 'docs'):
    files.extend(path for path in (root / directory).rglob('*')
                 if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc')
files.extend((dist / 'nfc_diagnostic_suite.fap', dist / 'BUILD.txt'))
files.extend(path for path in required if 'dist' in path.relative_to(root).parts)
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(set(files)):
        archive.write(path, Path('nfc-diagnostic-suite') / path.relative_to(root))
with zipfile.ZipFile(output) as archive:
    if archive.testzip() is not None:
        raise SystemExit('ZIP integrity failed')
    names = set(archive.namelist())
    if any('nfc-diagnostic-suite/' + str(path.relative_to(root)) not in names for path in required):
        raise SystemExit('ZIP missing required input')
checksums = [output, dist / 'nfc_diagnostic_suite.fap']
checksums.extend(dist / 'apps/NFC' / (app + '.fap') for app in apps)
(dist / 'SHA256SUMS.txt').write_text(''.join(
    f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(dist)}\n'
    for path in checksums))
print(f'{output}: {output.stat().st_size:,} bytes; ZIP integrity passed')
