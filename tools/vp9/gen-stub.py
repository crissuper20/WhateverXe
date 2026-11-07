#!/usr/bin/env python3
"""Assemble tools/vp9/factory-stub.s and print its bytes as a C++ initializer.

Usage: gen-stub.py            print the initializer for kern_tahoe_descriptor_policy.hpp
       gen-stub.py --bytes    print the raw hex (used by tests/tahoe_descriptor.py)
"""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]

def stub_bytes():
    with tempfile.TemporaryDirectory() as d:
        obj = pathlib.Path(d) / 'stub.o'
        subprocess.run(['xcrun', 'clang', '-c', '-arch', 'x86_64', str(root / 'tools/vp9/factory-stub.s'), '-o', str(obj)], check=True)
        relocs = subprocess.check_output(['xcrun', 'otool', '-r', str(obj)], text=True)
        assert 'Relocation information' not in relocs, 'stub must be position-resolved'
        dump = subprocess.check_output(['xcrun', 'otool', '-t', str(obj)], text=True)
    data = bytearray()
    for line in dump.splitlines()[2:]:
        fields = line.split()
        data += bytes.fromhex(''.join(fields[1:]))
    return bytes(data)

if __name__ == '__main__':
    b = stub_bytes()
    if '--bytes' in sys.argv:
        print(b.hex())
    else:
        rows = [','.join('0x%02x' % x for x in b[i:i + 16]) for i in range(0, len(b), 16)]
        print('constexpr uint8_t vp9Stub[] {\n ' + ',\n '.join(rows) + ',\n};')
