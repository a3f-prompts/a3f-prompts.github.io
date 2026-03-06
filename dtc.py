#!/usr/bin/env python3
"""
Minimal DTS to DTB compiler.

Compiles a .dts file into a flattened device tree blob.
Optionally reuses the string table layout from a template DTB.

Usage: dtc.py <input.dts> [-o output.dtb] [-t template.dtb]
"""

import sys
import struct
import re
import argparse

FDT_MAGIC = 0xd00dfeed
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_END = 9


def align4(b):
    """Pad bytearray to 4-byte alignment."""
    pad = (4 - len(b) % 4) % 4
    return b + b'\x00' * pad


class StringTable:
    def __init__(self, template_data=None):
        self.data = bytearray()
        self.lookup = {}  # name -> offset
        if template_data:
            self.data = bytearray(template_data)
            # Parse existing strings
            off = 0
            while off < len(self.data):
                end = self.data.index(0, off)
                name = self.data[off:end].decode()
                self.lookup[name] = off
                off = end + 1

    def get_or_add(self, name):
        if name in self.lookup:
            return self.lookup[name]
        off = len(self.data)
        self.lookup[name] = off
        self.data.extend(name.encode() + b'\x00')
        return off

    def to_bytes(self):
        return bytes(self.data)


class DTSParser:
    """Tokenizer + recursive descent parser for .dts files."""

    def __init__(self, text):
        self.text = text
        self.pos = 0

    def skip_ws_and_comments(self):
        while self.pos < len(self.text):
            # Skip whitespace
            if self.text[self.pos] in ' \t\n\r':
                self.pos += 1
                continue
            # Skip // line comments
            if self.text[self.pos:self.pos+2] == '//':
                nl = self.text.find('\n', self.pos)
                self.pos = nl + 1 if nl >= 0 else len(self.text)
                continue
            # Skip /* block comments */
            if self.text[self.pos:self.pos+2] == '/*':
                end = self.text.find('*/', self.pos)
                self.pos = end + 2 if end >= 0 else len(self.text)
                continue
            break

    def peek(self):
        self.skip_ws_and_comments()
        if self.pos >= len(self.text):
            return None
        return self.text[self.pos]

    def expect(self, ch):
        self.skip_ws_and_comments()
        if self.pos >= len(self.text) or self.text[self.pos] != ch:
            ctx = self.text[max(0, self.pos-20):self.pos+20]
            raise ValueError(f"Expected '{ch}' at pos {self.pos}, got: ...{ctx}...")
        self.pos += 1

    def read_name(self):
        """Read a node or property name: alphanumeric, -, _, ., #, @"""
        self.skip_ws_and_comments()
        start = self.pos
        while self.pos < len(self.text) and (
            self.text[self.pos].isalnum() or self.text[self.pos] in '-_.,#@+'):
            self.pos += 1
        if self.pos == start:
            ctx = self.text[max(0, self.pos-10):self.pos+20]
            raise ValueError(f"Expected name at pos {self.pos}: ...{ctx}...")
        return self.text[start:self.pos]

    def read_string(self):
        """Read a quoted string."""
        self.expect('"')
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] != '"':
            if self.text[self.pos] == '\\':
                self.pos += 1  # skip escaped char
            self.pos += 1
        s = self.text[start:self.pos]
        self.expect('"')
        # Handle escape sequences
        s = s.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')
        return s

    def read_cell_value(self):
        """Read a single cell value (hex or decimal)."""
        self.skip_ws_and_comments()
        start = self.pos
        if self.text[self.pos:self.pos+2] in ('0x', '0X'):
            self.pos += 2
            while self.pos < len(self.text) and self.text[self.pos] in '0123456789abcdefABCDEF':
                self.pos += 1
            return int(self.text[start:self.pos], 16)
        else:
            while self.pos < len(self.text) and self.text[self.pos].isdigit():
                self.pos += 1
            return int(self.text[start:self.pos])

    def read_bytestring(self):
        """Read [hex bytes]."""
        self.expect('[')
        self.skip_ws_and_comments()
        data = bytearray()
        while self.peek() != ']':
            self.skip_ws_and_comments()
            # Read two hex digits
            h = self.text[self.pos:self.pos+2]
            data.append(int(h, 16))
            self.pos += 2
            self.skip_ws_and_comments()
        self.expect(']')
        return bytes(data)

    def read_cell_list(self):
        """Read <cell values>."""
        self.expect('<')
        cells = []
        while self.peek() != '>':
            cells.append(self.read_cell_value())
            self.skip_ws_and_comments()
        self.expect('>')
        return cells

    def read_prop_value(self):
        """Read a property value, returns bytes.

        Handles: strings, string lists, cell arrays, bytestrings, and combinations.
        """
        self.skip_ws_and_comments()
        parts = []

        while True:
            ch = self.peek()
            if ch == '"':
                s = self.read_string()
                parts.append(s.encode() + b'\x00')
            elif ch == '<':
                cells = self.read_cell_list()
                parts.append(b''.join(struct.pack('>I', c) for c in cells))
            elif ch == '[':
                parts.append(self.read_bytestring())
            else:
                break

            self.skip_ws_and_comments()
            # Check for comma (string list continuation) or more data
            if self.peek() == ',':
                self.pos += 1
                self.skip_ws_and_comments()
                continue
            # If next is another value type, continue concatenating
            if self.peek() in ('"', '<', '['):
                continue
            break

        return b''.join(parts)

    def parse(self):
        """Parse a complete .dts file, return root node."""
        self.skip_ws_and_comments()
        # Skip /dts-v1/;
        if self.text[self.pos:].startswith('/dts-v1/'):
            self.pos += 8
            self.expect(';')

        # Parse root node
        self.expect('/')
        return self._parse_node('')

    def _parse_node(self, name):
        """Parse a node: { properties and children }."""
        self.expect('{')
        props = []
        children = []

        while self.peek() != '}':
            # Save position to distinguish property vs child node
            saved = self.pos
            n = self.read_name()
            self.skip_ws_and_comments()

            ch = self.peek()
            if ch == '=':
                # Property with value
                self.expect('=')
                val = self.read_prop_value()
                self.expect(';')
                props.append((n, val))
            elif ch == ';':
                # Boolean property (no value)
                self.expect(';')
                props.append((n, b''))
            elif ch == '{':
                # Child node
                children.append(self._parse_node(n))
                self.expect(';')
            else:
                ctx = self.text[max(0, self.pos-20):self.pos+20]
                raise ValueError(f"Unexpected '{ch}' after name '{n}' at pos {self.pos}: ...{ctx}...")

        self.expect('}')
        return (name, props, children)


def compile_node(node, strtab):
    """Compile a node into FDT struct bytes."""
    name, props, children = node
    out = bytearray()

    # FDT_BEGIN_NODE + name + padding
    out += struct.pack('>I', FDT_BEGIN_NODE)
    name_bytes = name.encode() + b'\x00'
    out += align4(name_bytes)

    # Properties
    for pname, pval in props:
        nameoff = strtab.get_or_add(pname)
        out += struct.pack('>III', FDT_PROP, len(pval), nameoff)
        out += align4(pval)

    # Child nodes
    for child in children:
        out += compile_node(child, strtab)

    # FDT_END_NODE
    out += struct.pack('>I', FDT_END_NODE)

    return bytes(out)


def compile_dtb(dts_text, template_dtb=None):
    """Compile DTS text into a DTB blob."""
    # Load template string table if provided
    if template_dtb:
        strings_off = struct.unpack('>I', template_dtb[12:16])[0]
        strings_size = struct.unpack('>I', template_dtb[32:36])[0]
        template_strings = template_dtb[strings_off:strings_off + strings_size]
        strtab = StringTable(template_strings)
    else:
        strtab = StringTable()

    # Parse
    parser = DTSParser(dts_text)
    root = parser.parse()

    # Compile struct
    dt_struct = compile_node(root, strtab)
    dt_struct += struct.pack('>I', FDT_END)

    dt_strings = strtab.to_bytes()

    # Build header (10 * 4 = 40 bytes)
    hdr_size = 40
    mem_rsvmap_off = hdr_size
    # mem_rsvmap: one empty entry (16 bytes of zeros)
    mem_rsvmap = b'\x00' * 16
    dt_struct_off = mem_rsvmap_off + len(mem_rsvmap)
    dt_strings_off = dt_struct_off + len(dt_struct)
    totalsize = dt_strings_off + len(dt_strings)

    header = struct.pack('>IIIIIIIIII',
                         FDT_MAGIC,
                         totalsize,
                         dt_struct_off,
                         dt_strings_off,
                         mem_rsvmap_off,
                         17,  # version
                         16,  # last_comp_version
                         0,   # boot_cpuid_phys
                         len(dt_strings),
                         len(dt_struct))

    return header + mem_rsvmap + dt_struct + dt_strings


def main():
    ap = argparse.ArgumentParser(description='Minimal DTS to DTB compiler')
    ap.add_argument('input', help='Input .dts file')
    ap.add_argument('-o', '--output', help='Output .dtb file', default=None)
    ap.add_argument('-t', '--template', help='Template DTB for string table layout')
    args = ap.parse_args()

    with open(args.input, 'r') as f:
        dts_text = f.read()

    template_dtb = None
    if args.template:
        with open(args.template, 'rb') as f:
            template_dtb = f.read()

    dtb = compile_dtb(dts_text, template_dtb)

    outfile = args.output or args.input.rsplit('.', 1)[0] + '.dtb'
    with open(outfile, 'wb') as f:
        f.write(dtb)
    print(f"Wrote {outfile} ({len(dtb)} bytes, strings: {struct.unpack('>I', dtb[32:36])[0]} bytes)")


if __name__ == '__main__':
    main()
