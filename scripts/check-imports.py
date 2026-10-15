#!/usr/bin/env python3
"""Check every suite FAP import, API metadata, and launcher icon against the SDK."""
import argparse
import csv
import hashlib
import os
from pathlib import Path
import struct
import subprocess


def elf_sections(data, layout=None):
    if data[:6] != b'\x7fELF\x01\x01' or len(data) < 52:
        raise ValueError('Expected little-endian ELF32 FAP')
    offset = struct.unpack_from('<I', data, 32)[0]
    stride, count, strings = struct.unpack_from('<HHH', data, 46)
    if stride < 40 or strings >= count or offset + count * stride > len(data):
        raise ValueError('Invalid ELF section table')
    headers = [struct.unpack_from('<10I', data, offset + index * stride) for index in range(count)]
    string_header = headers[strings]
    names = data[string_header[4]:string_header[4] + string_header[5]]
    result = {}
    for header in headers:
        if header[0] >= len(names):
            raise ValueError('Invalid ELF section name')
        end = names.find(b'\0', header[0])
        if end < 0:
            raise ValueError('Unterminated ELF section name')
        name = names[header[0]:end].decode('ascii')
        if layout is not None:
            layout[name] = {'size': header[5], 'flags': header[2]}
        if header[1] == 8:  # SHT_NOBITS occupies no file bytes.
            continue
        start, size = header[4:6]
        if start + size > len(data):
            raise ValueError('ELF section exceeds artifact')
        result[name] = data[start:start + size]
    return result


def check_imports(firmware, artifact, exports):
    nm = Path(os.environ.get('FBT_TOOLCHAIN_PATH', str(firmware))) / 'toolchain/current/bin/arm-none-eabi-nm'
    output = subprocess.check_output([str(nm), '-P', '-u', str(artifact)], text=True)
    imports = {line.split()[0] for line in output.splitlines() if line.strip()}
    missing = imports - exports
    if missing:
        raise ValueError('Unresolved Momentum API imports: ' + ', '.join(sorted(missing)))
    allowed_listener = {'nfc_listener_' + suffix for suffix in
                        ('alloc', 'free', 'start', 'stop', 'get_data', 'get_protocol', 'tx')}
    patterns = ('poller_write', 'listener_write', 'recover_key', 'nested_attack',
                'mfkey32_recover', 'mfkey32v2', 'lfrfid_worker_write', 't5577_write',
                'em4305_write', 'slix_poller_set_password', 'mf_desfire_poller_create',
                'mf_classic_poller_auth', 'mf_ultralight_poller_auth')
    forbidden = {name for name in imports if
                 (name.startswith('nfc_listener_') and name not in allowed_listener) or
                 any(part in name for part in patterns)}
    if forbidden:
        raise ValueError('Direct write/recovery API forbidden in diagnostics: ' + ', '.join(sorted(forbidden)))
    return len(imports)


def check_embedded_plugin(sections, artifact):
    """Validate Momentum's exact v1 FileBundler layout and embedded payload."""
    data = sections.get('.fapassets', b'')
    if len(data) < 36:
        raise ValueError('Missing embedded offline tools')
    magic, version, directories, files, signature_size = struct.unpack_from('<5I', data)
    if (magic, version, directories, files, signature_size) != (0x4F4C5A44, 1, 1, 1, 16):
        raise ValueError('Unexpected embedded asset layout')
    digest = hashlib.md5()
    offset = 36
    names = []
    for _ in range(2):
        if offset + 4 > len(data):
            raise ValueError('Truncated embedded asset name')
        size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if not 1 <= size <= 128 or offset + size > len(data):
            raise ValueError('Invalid embedded asset name length')
        name = data[offset:offset + size]
        if not name.endswith(b'\0') or b'\0' in name[:-1]:
            raise ValueError('Invalid embedded asset name')
        digest.update(name)
        names.append(name[:-1].decode('ascii'))
        offset += size
    if names != ['plugins', 'plugins/nfc_diag_tools.fal'] or offset + 4 > len(data):
        raise ValueError('Unexpected embedded offline tools path')
    size = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    payload = data[offset:]
    if len(payload) != size or payload != artifact.read_bytes():
        raise ValueError('Embedded offline tools differ from native FAL')
    digest.update(payload)
    if digest.digest() != data[20:36]:
        raise ValueError('Embedded asset signature mismatch')
    return len(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware', type=Path)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--icon', type=Path)
    parser.add_argument('--embedded-plugin', type=Path)
    args = parser.parse_args()
    exports = set()
    api = None
    with (args.firmware / 'targets/f7/api_symbols.csv').open(newline='') as source:
        for row in csv.reader(source):
            if len(row) >= 3 and row[0] in ('Function', 'Variable') and row[1] == '+':
                exports.add(row[2])
            elif len(row) >= 3 and row[0] == 'Version' and row[1] == '+':
                major, minor = map(int, row[2].split('.'))
                api = (major << 16) | minor
    sections = elf_sections(args.artifact.read_bytes())
    metadata = sections.get('.fapmeta', b'')
    if len(metadata) < 86 or struct.unpack_from('<IIIh', metadata) != (0x52474448, 1, api, 7):
        raise ValueError('FAP metadata/API mismatch')
    if args.icon:
        code = ('import sys; sys.path.insert(0, sys.argv[1]); '
                'from flipper.assets.icon import file2image; '
                'print(file2image(sys.argv[2]).data.hex())')
        python = Path(os.environ.get('FBT_TOOLCHAIN_PATH', str(args.firmware))) / 'toolchain/current/bin/python3'
        encoded = bytes.fromhex(subprocess.check_output(
            [str(python), '-c', code, str(args.firmware / 'scripts'), str(args.icon)], text=True).strip())
        if not metadata[52] or len(encoded) > 32 or metadata[53:85] != encoded.ljust(32, b'\0'):
            raise ValueError('Embedded launcher icon differs from source asset')
    count = check_imports(args.firmware, args.artifact, exports)
    print(f'{args.artifact.name}: {count} enabled imports; API verified' + ('; launcher icon verified' if args.icon else ''))
    if args.embedded_plugin:
        size = check_embedded_plugin(sections, args.embedded_plugin)
        layout = {}
        plugin_sections = elf_sections(args.embedded_plugin.read_bytes(), layout)
        loaded = {name: info['size'] for name, info in layout.items()
                  if not name.startswith(('.ARM.', '.rel.ARM.', '.fast.rel.ARM.'))
                  and (info['flags'] & 2 or name.startswith('.fast.rel.'))}
        mapped = sum(size for name, size in loaded.items() if not name.startswith('.fast.rel.'))
        relocations = sum(size for name, size in loaded.items() if name.startswith('.fast.rel.'))
        if mapped + relocations + 4096 + 12288 > 32768 or max(loaded.values(), default=0) + 1024 > 12288:
            raise ValueError('Offline FAL exceeds measured loader RAM guards')
        print(f'Offline RAM gate: {mapped} mapped + {relocations} relocation bytes; 32 KiB load reserve fits')
        plugin_metadata = plugin_sections.get('.fapmeta', b'')
        if len(plugin_metadata) < 86 or struct.unpack_from('<IIIh', plugin_metadata) != (0x52474448, 1, api, 7):
            raise ValueError('Embedded FAL metadata/API mismatch')
        plugin_imports = check_imports(args.firmware, args.embedded_plugin, exports)
        print(f'Embedded offline tools: {size} bytes exact match; {plugin_imports} enabled imports; API verified')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
