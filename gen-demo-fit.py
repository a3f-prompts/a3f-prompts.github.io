#!/usr/bin/env python3
"""Generate demo.fit: a signed FIT image used by demo.html.

Unlike test-x509.fit, the hash values here are real sha256 digests of the
image data, so the before/after hashes shown by the tool are meaningful.
The signature values are random bytes -- nothing verifies them, the point is
to exercise the signed-configuration code paths.

Reuses FdtBuilder from gen-test-fit.py (hyphenated name, hence importlib).
"""

import hashlib
import importlib.util
import os
import struct

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'gen_test_fit', os.path.join(_HERE, 'gen-test-fit.py'))
_gtf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gtf)
FdtBuilder = _gtf.FdtBuilder


def make_kernel(size=4096):
    """A fake kernel payload: ARM64 Image header magic + filler."""
    hdr = struct.pack('<IIQQQQQQ',
                      0,            # code0
                      0,            # code1
                      0x80000,      # text_offset
                      size,         # image_size
                      0,            # flags
                      0, 0, 0)      # res2..res4
    hdr += b'ARM\x64'               # magic
    return hdr + b'DEMO_KERNEL' + b'\xa5' * (size - len(hdr) - 11)


def make_dtb():
    """A small DTB for the flat_dt image -- this is what /model rewriting hits."""
    b = FdtBuilder()
    b.begin_node('')
    b.prop_str('model', 'Demo Board Rev B')
    b.prop_str('compatible', 'demo,board')
    b.prop_u32('#address-cells', 2)
    b.prop_u32('#size-cells', 2)
    b.begin_node('chosen')
    b.prop_str('bootargs', 'console=ttyS0,115200 root=/dev/mmcblk0p2 rw')
    b.end_node()
    b.begin_node('memory@40000000')
    b.prop_str('device_type', 'memory')
    b.prop_bytes('reg', struct.pack('>QQ', 0x40000000, 0x20000000))
    b.end_node()
    b.end_node()
    b.finish()
    return b.build()


def make_ramdisk(size=2048):
    """A fake initramfs: cpio newc magic + filler."""
    return b'070701' + b'\x00' * (size - 6)


def add_image(b, name, desc, img_type, data, os_name=None,
              load=None, entry=None):
    """Emit an /images child with a correct sha256 hash-1 subnode."""
    b.begin_node(name)
    b.prop_str('description', desc)
    b.prop_str('type', img_type)
    b.prop_str('arch', 'arm64')
    b.prop_str('compression', 'none')
    if os_name:
        b.prop_str('os', os_name)
    b.prop_bytes('data', data)
    if load is not None:
        b.prop_u32('load', load)
    if entry is not None:
        b.prop_u32('entry', entry)
    b.begin_node('hash-1')
    b.prop_str('algo', 'sha256')
    b.prop_bytes('value', hashlib.sha256(data).digest())
    b.end_node()
    b.end_node()


def add_signature(b, config_name, images):
    """Emit a signature-1 subnode covering the given (role, image) pairs."""
    hashed = ['/', '/configurations/' + config_name]
    for _, img in images:
        hashed.append('/images/' + img)
        hashed.append('/images/' + img + '/hash-1')

    b.begin_node('signature-1')
    b.prop_str('algo', 'sha256,rsa2048')
    b.prop_str('key-name-hint', 'demo-key')
    b.prop_u32('sign-timestamp', 0x67000000)
    b.prop_stringlist('sign-images', [role for role, _ in images])
    b.prop_stringlist('hashed-nodes', hashed)
    b.prop_bytes('hashed-strings', struct.pack('>II', 0, 0x200))
    b.prop_bytes('value', os.urandom(256))
    b.end_node()


def build_fit():
    kernel_data = make_kernel()
    dtb_data = make_dtb()
    ramdisk_data = make_ramdisk()

    b = FdtBuilder()

    b.begin_node('')
    b.prop_str('description', 'Demo FIT image (signed)')
    b.prop_u32('#address-cells', 1)
    b.prop_str('creator', 'gen-demo-fit.py')

    b.begin_node('images')
    add_image(b, 'kernel-1', 'Linux kernel 6.6.0', 'kernel', kernel_data,
              os_name='linux', load=0x40080000, entry=0x40080000)
    add_image(b, 'fdt-1', 'Demo Board device tree', 'flat_dt', dtb_data)
    add_image(b, 'ramdisk-1', 'Initramfs', 'ramdisk', ramdisk_data,
              os_name='linux')
    b.end_node()

    b.begin_node('configurations')
    b.prop_str('default', 'conf-1')

    # Full boot configuration: kernel + fdt + ramdisk, all signed.
    imgs = [('kernel', 'kernel-1'), ('fdt', 'fdt-1'), ('ramdisk', 'ramdisk-1')]
    b.begin_node('conf-1')
    b.prop_str('description', 'Demo Board -- kernel, DTB and initramfs')
    b.prop_str('kernel', 'kernel-1')
    b.prop_str('fdt', 'fdt-1')
    b.prop_str('ramdisk', 'ramdisk-1')
    add_signature(b, 'conf-1', imgs)
    b.end_node()

    # Recovery configuration without a ramdisk, also signed.
    imgs = [('kernel', 'kernel-1'), ('fdt', 'fdt-1')]
    b.begin_node('conf-2')
    b.prop_str('description', 'Demo Board -- recovery, no initramfs')
    b.prop_str('kernel', 'kernel-1')
    b.prop_str('fdt', 'fdt-1')
    add_signature(b, 'conf-2', imgs)
    b.end_node()

    b.end_node()  # /configurations

    b.end_node()  # root
    b.finish()
    return b.build()


if __name__ == '__main__':
    data = build_fit()
    outpath = os.path.join(_HERE, 'demo.fit')
    with open(outpath, 'wb') as f:
        f.write(data)
    print(f'Wrote {len(data)} bytes to {outpath}')
    print('  - kernel-1, fdt-1, ramdisk-1 with real sha256 hash-1 subnodes')
    print('  - conf-1 (default) and conf-2, both signed sha256,rsa2048')
