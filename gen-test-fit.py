#!/usr/bin/env python3
"""Generate a sample FIT image with an X.509-signed image for manual testing."""

import struct
import os

FDT_MAGIC = 0xd00dfeed
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_END = 9

class FdtBuilder:
    def __init__(self):
        self.struct_data = bytearray()
        self.strings = bytearray()
        self.string_offsets = {}

    def _str_offset(self, name):
        if name in self.string_offsets:
            return self.string_offsets[name]
        off = len(self.strings)
        self.string_offsets[name] = off
        self.strings += name.encode() + b'\x00'
        return off

    def _pad4(self):
        while len(self.struct_data) % 4:
            self.struct_data += b'\x00'

    def begin_node(self, name):
        self.struct_data += struct.pack('>I', FDT_BEGIN_NODE)
        self.struct_data += name.encode() + b'\x00'
        self._pad4()

    def end_node(self):
        self.struct_data += struct.pack('>I', FDT_END_NODE)

    def prop_str(self, name, value):
        data = value.encode() + b'\x00'
        self.struct_data += struct.pack('>III', FDT_PROP, len(data), self._str_offset(name))
        self.struct_data += data
        self._pad4()

    def prop_u32(self, name, value):
        data = struct.pack('>I', value)
        self.struct_data += struct.pack('>III', FDT_PROP, 4, self._str_offset(name))
        self.struct_data += data

    def prop_stringlist(self, name, values):
        data = b''.join(v.encode() + b'\x00' for v in values)
        self.struct_data += struct.pack('>III', FDT_PROP, len(data), self._str_offset(name))
        self.struct_data += data
        self._pad4()

    def prop_bytes(self, name, data):
        self.struct_data += struct.pack('>III', FDT_PROP, len(data), self._str_offset(name))
        self.struct_data += data
        self._pad4()

    def finish(self):
        self.struct_data += struct.pack('>I', FDT_END)

    def build(self):
        hdr_size = 40
        mem_rsv = b'\x00' * 16  # empty reservation block (one null entry)

        off_mem = hdr_size
        off_struct = off_mem + len(mem_rsv)
        off_strings = off_struct + len(self.struct_data)
        totalsize = off_strings + len(self.strings)

        header = struct.pack('>IIIIIIIIII',
            FDT_MAGIC,
            totalsize,
            off_struct,
            off_strings,
            off_mem,
            17,         # version
            16,         # last_comp_version
            0,          # boot_cpuid
            len(self.strings),
            len(self.struct_data),
        )

        return header + mem_rsv + bytes(self.struct_data) + bytes(self.strings)


def make_fake_kernel(size=256):
    """A fake kernel payload."""
    return b'\x00' * 4 + b'FAKE_KERNEL' + b'\xff' * (size - 15)


def make_fake_dtb():
    """A minimal DTB for the flat_dt image."""
    b = FdtBuilder()
    b.begin_node('')  # root
    b.prop_str('model', 'Test Board Rev A')
    b.prop_str('compatible', 'test,board')
    b.prop_u32('#address-cells', 2)
    b.prop_u32('#size-cells', 2)
    b.end_node()
    b.finish()
    return b.build()


def make_fake_x509(size=512):
    """Fake data that starts with X.509 DER header magic (0x30 0x82)."""
    # 0x30 = ASN.1 SEQUENCE, 0x82 = length uses next 2 bytes
    length = size - 4
    return b'\x30\x82' + struct.pack('>H', length) + os.urandom(length)


def make_fake_ramdisk(size=128):
    """A fake ramdisk (cpio-ish)."""
    return b'070701' + b'\x00' * (size - 6)


def build_fit():
    kernel_data = make_fake_kernel()
    dtb_data = make_fake_dtb()
    x509_data = make_fake_x509()
    ramdisk_data = make_fake_ramdisk()

    b = FdtBuilder()

    # Root
    b.begin_node('')
    b.prop_str('description', 'Test FIT with X.509 image')
    b.prop_u32('#address-cells', 1)

    # /images
    b.begin_node('images')

    # kernel
    b.begin_node('kernel-1')
    b.prop_str('description', 'Linux kernel')
    b.prop_str('type', 'kernel')
    b.prop_str('arch', 'arm')
    b.prop_str('compression', 'none')
    b.prop_str('os', 'linux')
    b.prop_bytes('data', kernel_data)
    b.prop_u32('load', 0x40008000)
    b.prop_u32('entry', 0x40008000)
    # hash
    b.begin_node('hash-1')
    b.prop_str('algo', 'sha256')
    b.prop_bytes('value', b'\x00' * 32)
    b.end_node()
    b.end_node()

    # flat_dt
    b.begin_node('fdt-1')
    b.prop_str('description', 'Test Board device tree')
    b.prop_str('type', 'flat_dt')
    b.prop_str('arch', 'arm')
    b.prop_str('compression', 'none')
    b.prop_bytes('data', dtb_data)
    b.begin_node('hash-1')
    b.prop_str('algo', 'sha256')
    b.prop_bytes('value', b'\x00' * 32)
    b.end_node()
    b.end_node()

    # ramdisk
    b.begin_node('ramdisk-1')
    b.prop_str('description', 'Initramfs')
    b.prop_str('type', 'ramdisk')
    b.prop_str('arch', 'arm')
    b.prop_str('compression', 'none')
    b.prop_str('os', 'linux')
    b.prop_bytes('data', ramdisk_data)
    b.begin_node('hash-1')
    b.prop_str('algo', 'sha256')
    b.prop_bytes('value', b'\x00' * 32)
    b.end_node()
    b.end_node()

    # X.509-signed firmware image
    b.begin_node('firmware-1')
    b.prop_str('description', 'OP-TEE with X.509 signature')
    b.prop_str('type', 'firmware')
    b.prop_str('arch', 'arm')
    b.prop_str('compression', 'none')
    b.prop_str('os', 'tee')
    b.prop_bytes('data', x509_data)
    b.prop_u32('load', 0x4e000000)
    b.prop_u32('entry', 0x4e000000)
    b.end_node()

    b.end_node()  # /images

    # /configurations
    b.begin_node('configurations')
    b.prop_str('default', 'conf-1')

    b.begin_node('conf-1')
    b.prop_str('description', 'Test Board configuration')
    b.prop_str('kernel', 'kernel-1')
    b.prop_str('fdt', 'fdt-1')
    b.prop_str('ramdisk', 'ramdisk-1')
    # signed config
    b.begin_node('signature-1')
    b.prop_str('algo', 'sha256,rsa2048')
    b.prop_str('key-name-hint', 'dev-key')
    b.prop_bytes('value', os.urandom(256))
    b.end_node()
    b.end_node()

    b.end_node()  # /configurations

    b.end_node()  # root
    b.finish()
    return b.build()


if __name__ == '__main__':
    data = build_fit()
    outpath = os.path.join(os.path.dirname(__file__), 'test-x509.fit')
    with open(outpath, 'wb') as f:
        f.write(data)
    print(f'Wrote {len(data)} bytes to {outpath}')
    print(f'  - kernel-1: normal kernel image')
    print(f'  - fdt-1: device tree blob')
    print(f'  - ramdisk-1: fake ramdisk')
    print(f'  - firmware-1: data starts with 0x30 0x82 (X.509 magic)')
    print(f'  - conf-1: signed configuration (sha256,rsa2048)')
