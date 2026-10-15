#!/usr/bin/env python3
"""Check every import, the launcher icon, and optional embedded FAL against the SDK."""
import argparse
import csv
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile


def elf_sections(data):
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
        if header[1] == 8:  # SHT_NOBITS occupies no file bytes.
            continue
        start, size = header[4:6]
        if start + size > len(data):
            raise ValueError('ELF section exceeds artifact')
        result[name] = data[start:start + size]
    return result


def embedded_files(bundle):
    if len(bundle) < 36:
        raise ValueError('Missing FAP assets header')
    magic, version, directories, files, signature_size = struct.unpack_from('<5I', bundle)
    if (magic, version, signature_size) != (0x4F4C5A44, 1, 16):
        raise ValueError('Unsupported FAP assets format')
    cursor = 36
    digest = hashlib.md5()

    def take(size):
        nonlocal cursor
        if cursor + size > len(bundle):
            raise ValueError('Truncated FAP assets')
        value = bundle[cursor:cursor + size]
        cursor += size
        return value

    def number():
        return struct.unpack('<I', take(4))[0]

    def path():
        value = take(number())
        if not value or value[-1:] != b'\0' or b'\0' in value[:-1]:
            raise ValueError('Invalid FAP asset path')
        digest.update(value)
        return value[:-1].decode('ascii')

    for _ in range(directories):
        path()
    result = {}
    for _ in range(files):
        name = path()
        content = take(number())
        digest.update(content)
        if name in result:
            raise ValueError('Duplicate FAP asset path')
        result[name] = content
    if cursor != len(bundle) or digest.digest() != bundle[20:36]:
        raise ValueError('FAP assets integrity mismatch')
    return result


def check_imports(firmware, artifact, exports, profile):
    nm = firmware / 'toolchain/current/bin/arm-none-eabi-nm'
    output = subprocess.check_output([str(nm), '-P', '-u', str(artifact)], text=True)
    imports = {line.split()[0] for line in output.splitlines() if line.strip()}
    missing = imports - exports
    if missing:
        raise ValueError('Unresolved Momentum API imports: ' + ', '.join(sorted(missing)))
    if profile == 'diagnostic':
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware', type=Path)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--profile', choices=('diagnostic', 'companion'), default='diagnostic')
    parser.add_argument('--icon', type=Path)
    parser.add_argument('--require-embedded-plugin')
    args = parser.parse_args()
    if args.profile == 'companion' and args.artifact.stem not in ('mfkey', 'nfc_magic', 'picopass'):
        parser.error('Companion profile requires a named native companion')
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
        python = args.firmware / 'toolchain/current/bin/python3'
        encoded = bytes.fromhex(subprocess.check_output(
            [str(python), '-c', code, str(args.firmware / 'scripts'), str(args.icon)], text=True).strip())
        if not metadata[52] or len(encoded) > 32 or metadata[53:85] != encoded.ljust(32, b'\0'):
            raise ValueError('Embedded launcher icon differs from source asset')
    count = check_imports(args.firmware, args.artifact, exports, args.profile)
    if args.require_embedded_plugin:
        files = embedded_files(sections.get('.fapassets', b''))
        matches = [data for name, data in files.items() if Path(name).name == args.require_embedded_plugin]
        if len(matches) != 1:
            raise ValueError('Expected exactly one embedded ' + args.require_embedded_plugin)
        with tempfile.TemporaryDirectory(prefix='diag-fal-') as directory:
            plugin = Path(directory) / args.require_embedded_plugin
            plugin.write_bytes(matches[0])
            elf_sections(matches[0])
            plugin_count = check_imports(args.firmware, plugin, exports, 'companion')
        print(f'Embedded {args.require_embedded_plugin}: {plugin_count} enabled imports; assets integrity passed')
    print(f'{args.artifact.name}: {count} enabled imports; API and launcher icon verified')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
