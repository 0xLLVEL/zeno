"""Retarget a stock Luau blob onto a permuted client build.

Two things differ from upstream bytecode and both live in the blob's bytes, not
in the loader: the opcode byte of every instruction, and the tag byte of every
constant. The loader applies its own canonical -> runtime substitution on load,
so the blob has to carry *canonical* opcodes; a stock compiler emits LOP-order
bytes instead.

usage: remap.py <in.bin> <out.bin> --opmap <256-byte table> [--const-shift 1]

The opcode table is indexed by LOP number and yields the canonical byte, which
is exactly the layout the patched BytecodeBuilder reads from ZENO_OPMAP, so the
same file drives both paths.
"""

import sys
import struct

LBC_CONSTANT_NIL = 0
LBC_CONSTANT_BOOLEAN = 1
LBC_CONSTANT_NUMBER = 2
LBC_CONSTANT_STRING = 3
LBC_CONSTANT_IMPORT = 4
LBC_CONSTANT_TABLE = 5
LBC_CONSTANT_CLOSURE = 6
LBC_CONSTANT_VECTOR = 7
LBC_CONSTANT_TABLE_WITH_CONSTANTS = 8
LBC_CONSTANT_INTEGER = 9
LBC_CONSTANT_CLASS_SHAPE = 10
LBC_CONSTANT_VECTORD = 11

DEFAULT_WIDTHS = None


class Reader:
    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def byte(self):
        value = self.data[self.pos]
        self.pos += 1
        return value

    def varint(self):
        result = 0
        shift = 0
        while True:
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result
            shift += 7

    def skip(self, count):
        self.pos += count


def remap_proto(data, start, end, opmap, widths, const_shift):
    reader = Reader(data, start)
    reader.skip(5)  # maxstacksize, numparams, numups, isvararg, flags
    typesize = reader.varint()
    reader.skip(typesize)

    sizecode = reader.varint()
    code_at = reader.pos
    pc = 0
    while pc < sizecode:
        at = code_at + pc * 4
        word = struct.unpack_from("<I", data, at)[0]
        op = word & 0xFF
        canonical = opmap[op]
        data[at] = canonical
        pc += widths[op]
    reader.pos = code_at + sizecode * 4

    sizek = reader.varint()
    for _ in range(sizek):
        tag_at = reader.pos
        tag = reader.byte()
        if tag == LBC_CONSTANT_NIL:
            continue
        if const_shift:
            data[tag_at] = tag + const_shift
        if tag == LBC_CONSTANT_BOOLEAN:
            reader.skip(1)
        elif tag == LBC_CONSTANT_NUMBER:
            reader.skip(8)
        elif tag == LBC_CONSTANT_INTEGER:
            reader.skip(1)
            reader.varint()
        elif tag == LBC_CONSTANT_STRING or tag == LBC_CONSTANT_CLOSURE:
            reader.varint()
        elif tag == LBC_CONSTANT_IMPORT:
            reader.skip(4)
        elif tag == LBC_CONSTANT_VECTOR:
            reader.skip(16)
        elif tag == LBC_CONSTANT_VECTORD:
            reader.skip(32)
        elif tag == LBC_CONSTANT_TABLE:
            for _ in range(reader.varint()):
                reader.varint()
        elif tag == LBC_CONSTANT_TABLE_WITH_CONSTANTS:
            for _ in range(reader.varint()):
                reader.varint()
                reader.skip(4)
        elif tag == LBC_CONSTANT_CLASS_SHAPE:
            read_class_shape(reader)
        else:
            raise SystemExit(f"unknown constant tag {tag} at {tag_at}")

    assert reader.pos <= end, f"proto overran its slice: {reader.pos} > {end}"


def read_class_shape(reader):
    reader.varint()  # name
    for _ in range(reader.varint()):
        reader.varint()  # key
    for _ in range(reader.varint()):
        reader.varint()  # key
    for _ in range(reader.varint()):
        reader.varint()  # key
        reader.varint()  # method proto


def remap(blob, opmap, widths, const_shift):
    data = bytearray(blob)
    reader = Reader(data)
    reader.byte()  # version
    reader.byte()  # types version
    for _ in range(reader.varint()):
        reader.skip(reader.varint())
    while True:
        index = reader.byte()
        if index == 0:
            break
        reader.varint()
    count = reader.varint()
    for _ in range(count):
        size = reader.varint()
        start = reader.pos
        end = start + size
        remap_proto(data, start, end, opmap, widths, const_shift)
        reader.pos = end
    return bytes(data)


def main(argv):
    if len(argv) < 3:
        raise SystemExit(
            "usage: remap.py <in.bin> <out.bin> [--opmap <table>] [--widths <table>] [--const-shift n]"
        )
    source, target = argv[1], argv[2]
    opmap_path = None
    widths_path = None
    const_shift = 0
    index = 3
    while index < len(argv):
        if argv[index] == "--opmap":
            opmap_path = argv[index + 1]
            index += 2
        elif argv[index] == "--widths":
            widths_path = argv[index + 1]
            index += 2
        elif argv[index] == "--const-shift":
            const_shift = int(argv[index + 1], 0)
            index += 2
        else:
            raise SystemExit(f"unknown flag {argv[index]}")

    opmap = list(range(256))
    if opmap_path:
        raw = open(opmap_path, "rb").read()
        for i, byte in enumerate(raw[:256]):
            opmap[i] = byte

    widths = [1] * 256
    if widths_path:
        raw = open(widths_path, "rb").read()
        for i, byte in enumerate(raw[:256]):
            widths[i] = byte or 1

    blob = open(source, "rb").read()
    out = remap(blob, opmap, widths, const_shift)
    open(target, "wb").write(out)
    print(f"remap {source} -> {target} ({len(out)} bytes, const shift {const_shift})")


if __name__ == "__main__":
    main(sys.argv)
