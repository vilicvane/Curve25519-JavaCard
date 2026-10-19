#!/usr/bin/env python3
"""Prints the Import and ConstantPool components of a JavaCard CAP file.

A CAP file links against other packages purely by (package token, class token, method token): it
does not store the names of the classes or methods it calls. This tool decodes those references so
that a rebuilt CAP can be compared with the original Curve25519.cap.

The CAP produced by the JavaCard converter is a JAR, so the components are read straight out of the
archive; a bare component file is also accepted.

Usage: cpdump.py <cap-or-component> [more...]
"""

import sys
import zipfile

# External references in the original Curve25519.cap, keyed by (class token, method token).
# package token 3 is JCOPX (d276000085304a434f5058 1.24).
JOPX_AID = bytes.fromhex('d276000085304a434f5058')
JOPX_PACKAGE_NAME = {
    0: 'java/lang',
    1: 'javacard/security',
    2: 'javacard/framework',
    3: 'JCOPX',
}
JOPX_METHODS = {
    (1, 2): 'sign',
    (1, 3): 'verify',
    (1, 13): 'keyAgreement',
    (11, 1): 'createKey',
    (11, 2): 'genKeyPair',
}
JOPX_CLASSES = {9: 'private-key interface', 10: 'public-key interface'}


def components(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            result = {}
            for name in archive.namelist():
                if name.endswith('.cap') and '/javacard/' in name:
                    result[name.rsplit('/', 1)[-1][:-4]] = archive.read(name)
            return result
    with open(path, 'rb') as file:
        data = file.read()
    return {path.rsplit('/', 1)[-1][:-4]: data}


def show_imports(data):
    assert data[0] == 4, 'not an Import component: tag=%d' % data[0]
    body = data[3:]
    # body[0] is the package count; the package token is the index, there is no explicit field for it.
    offset = 1
    token = 0
    while offset < len(body):
        minor = body[offset]
        major = body[offset + 1]
        length = body[offset + 2]
        aid = body[offset + 3:offset + 3 + length]
        label = '  <- JCOPX' if aid == JOPX_AID else ''
        print('import token %d: %s %d.%d%s' % (token, aid.hex(), major, minor, label))
        offset += 3 + length
        token += 1


def show_constant_pool(data):
    assert data[0] == 5, 'not a ConstantPool component: tag=%d' % data[0]
    body = data[3:]
    count = (body[0] << 8) | body[1]
    offset = 2
    for index in range(count):
        tag = body[offset]
        ref = (body[offset + 1] << 8) | body[offset + 2]
        token = body[offset + 3]
        raw = body[offset:offset + 4].hex()
        offset += 4
        if ref & 0x8000:
            package = (ref >> 8) & 0x7F
            clazz = ref & 0xFF
            if tag == 6:
                note = JOPX_METHODS.get((clazz, token), '') if package == 3 else ''
                print('%2d %s  static method  pkg=%d cls=%d tok=%d %s%s'
                      % (index, raw, package, clazz, token, JOPX_PACKAGE_NAME.get(package, '?'),
                         (' = ' + note) if note else ''))
            elif tag == 1:
                note = JOPX_CLASSES.get(clazz, '') if package == 3 else ''
                print('%2d %s  class         pkg=%d cls=%d %s%s'
                      % (index, raw, package, clazz, JOPX_PACKAGE_NAME.get(package, '?'),
                         (' = ' + note) if note else ''))
            else:
                print('%2d %s  tag=%d ref=0x%04x tok=%d' % (index, raw, tag, ref, token))
        else:
            print('%2d %s  internal tag=%d ref=0x%04x tok=%d'
                  % (index, raw, tag, ref, token))
    assert offset == len(body), (offset, len(body))


def show(path):
    found = components(path)
    print('== %s' % path)
    if 'Import' in found:
        show_imports(found['Import'])
    if 'ConstantPool' in found:
        show_constant_pool(found['ConstantPool'])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('usage: cpdump.py <cap-or-component> [more...]\n')
        sys.exit(1)
    for argument in sys.argv[1:]:
        show(argument)
