"""Decode a zeno blob into (proto, instruction) listings.

Reads the container magic, then walks the Luau bytecode the same way the
client's loader will, and names every opcode byte through
`opmap_guess.json` (LOP name -> client canonical byte).

Usage:
    python decode.py <blob.bc>
"""

import json
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mkluau import MAGIC, read_varint

HERE = os.path.dirname(os.path.abspath(__file__))

WIDE = {
    "NEWTABLE", "SETLIST", "LOADKX", "JUMPX", "GETGLOBAL", "SETGLOBAL",
    "GETIMPORT", "GETTABLEKS", "SETTABLEKS", "NAMECALL", "JUMPIFEQ",
    "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
    "FORGLOOP", "FASTCALL3", "FASTCALL2", "FASTCALL2K", "JUMPXEQKNIL",
    "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS", "GETUDATAKS", "SETUDATAKS",
    "NAMECALLUDATA", "NEWCLASSMEMBER", "CALLFB", "CMPPROTO", "NEWCLASS",
    "CONSTRUCT", "FINCONSTRUCT", "GETPRIVATEFIELD", "SETPRIVATEFIELD",
}


def load_names():
    measured = json.load(open(os.path.join(HERE, "opmap_guess.json"), "r", encoding="utf-8"))
    return {entry["byte"]: name for name, entry in measured.items()}


def main(path):
    names = load_names()
    data = open(path, "rb").read()
    if data[:8] != MAGIC:
        raise SystemExit("missing container magic")

    off = 8
    version = data[off]
    typesversion = data[off + 1]
    off += 2

    nstrings, off = read_varint(data, off)
    strings = []
    for _ in range(nstrings):
        n, off = read_varint(data, off)
        strings.append(data[off:off + n])
        off += n

    if typesversion == 3:
        while data[off] != 0:
            off += 1
            _, off = read_varint(data, off)
        off += 1

    nprotos, off = read_varint(data, off)
    print(f"version {version} types {typesversion} strings {nstrings} protos {nprotos}")

    unknown = []
    for p in range(nprotos):
        size, off = read_varint(data, off)
        start = off
        maxstack, nparams, nups, is_vararg, flags = data[off:off + 5]
        off += 5
        typesize, off = read_varint(data, off)
        off += typesize
        sizecode, off = read_varint(data, off)
        words = list(struct.unpack_from(f"<{sizecode}I", data, off))
        off += 4 * sizecode

        sizek, off = read_varint(data, off)
        consts = []
        for _ in range(sizek):
            tag = data[off]
            off += 1
            if tag == 0:
                consts.append("nil")
            elif tag == 1:
                consts.append(f"bool {bool(data[off])}")
                off += 1
            elif tag == 3:
                consts.append(f"num {struct.unpack_from('<d', data, off)[0]!r}")
                off += 8
            elif tag == 6:
                idx, off = read_varint(data, off)
                consts.append(f"str {strings[idx]!r}")
            elif tag == 12:
                consts.append("vec " + data[off:off + 16].hex())
                off += 16
            else:
                consts.append(f"tag {tag}")

        print(f"\nproto {p}: stack {maxstack} params {nparams} nups {nups} "
              f"vararg {is_vararg} flags {flags:#x} code {sizecode} k {sizek}")
        if consts:
            print("  k: " + ", ".join(f"[{i}] {c}" for i, c in enumerate(consts)))

        i = 0
        while i < len(words):
            word = words[i]
            byte = word & 0xFF
            name = names.get(byte)
            if name is None:
                name = f"??{byte:02X}"
                unknown.append((p, i, byte))
            a = (word >> 8) & 0xFF
            b = (word >> 16) & 0xFF
            c = (word >> 24) & 0xFF
            aux = ""
            if name in WIDE:
                if i + 1 < len(words):
                    aux = f" aux={words[i + 1]}"
                i += 1
            print(f"  {i - (1 if aux else 0):3d} {word:08X} {name:<14} A={a} B={b} C={c}{aux}")
            i += 1

        off = start + size

    if unknown:
        print(f"\nUNKNOWN OPCODE BYTES: {unknown}")
    else:
        print("\nall opcode bytes resolve through the derived map")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
