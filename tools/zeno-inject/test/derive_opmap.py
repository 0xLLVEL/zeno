"""Derive the client's canonical opcode map straight from the image.

The client's loader rewrites every instruction word before the interpreter
sees it:

    word = (word & 0xFFFFFF00) | T[word & 0xFF]

where `T` is a 256-byte bijection at rva 0x735B280 mapping the byte the blob
carries (the "canonical" byte) to the byte the interpreter dispatches on (the
"dispatch" byte). The interpreter's own dispatch table (byte table at
0x26933F4, offset table at 0x2693278) turns a dispatch byte into a handler,
and `SC` at rva 0x735B380, indexed by the dispatch byte, holds the LOP number
that handler implements.

So `SC[T[canonical]]` names the opcode a canonical byte selects. Inverting it
gives, for every LOP the client actually implements, the exact byte a compiled
blob must contain. 94 of the 95 upstream LOPs are implemented; the missing one
is CAPTURE, which only exists during analysis and is never emitted into a
loadable chunk.

Usage:
    python derive_opmap.py [path to decrypted client image]
"""

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DEFAULT_IMAGE = r"C:\Users\ezan\Downloads\Programs\RobloxPlayerBeta-decrypted.exe"

LOADER_TABLE = 0x735B280
LOP_TABLE = 0x735B380
DISPATCH_BYTE_TABLE = 0x26933F4
DISPATCH_OFFSET_TABLE = 0x2693278
FASTFAIL = 0x2692B8D

sys.path.insert(0, HERE)
from mkluau import LOP_ORDER  # noqa: E402

# LOP -> instruction width in 32-bit words, as the client's compiler emits it.
# Taken from `luaucomp.exe --tables` (tab_w.bin), which is the same Luau the
# client ships, so it describes the client encoding rather than upstream.
WIDTHS = None


def derive(image_path):
    image = open(image_path, "rb").read()
    rewrite = image[LOADER_TABLE:LOADER_TABLE + 256]
    lop_of_dispatch = image[LOP_TABLE:LOP_TABLE + 256]

    by_lop = {}
    for canonical in range(256):
        dispatch = rewrite[canonical]
        if not 1 <= dispatch <= 254:
            continue
        slot = image[DISPATCH_BYTE_TABLE + dispatch - 1]
        handler = struct.unpack_from("<i", image, DISPATCH_OFFSET_TABLE + slot * 4)[0] & 0xFFFFFFFF
        if handler == FASTFAIL:
            continue
        by_lop[lop_of_dispatch[dispatch]] = canonical
    return by_lop


def main(image_path):
    by_lop = derive(image_path)
    widths = load_widths()

    measured = {}
    for index, name in enumerate(LOP_ORDER):
        if index not in by_lop:
            continue
        entry = {"byte": by_lop[index], "score": 1.0}
        if widths is not None:
            entry["width"] = widths[index]
        measured[name] = entry

    guess = os.path.join(HERE, "opmap_guess.json")
    with open(guess, "w", encoding="utf-8") as f:
        json.dump(measured, f, indent=2, sort_keys=True)

    table = bytearray(range(256))
    for index, name in enumerate(LOP_ORDER):
        if name in measured:
            table[index] = measured[name]["byte"]

    with open(os.path.join(HERE, "opmap_client.bin"), "wb") as f:
        f.write(bytes(table))

    with open(os.path.join(REPO, "zeno-core", "config", "luau_opmap.bin"), "wb") as f:
        f.write(bytes(table[:len(LOP_ORDER)]))

    missing = [name for index, name in enumerate(LOP_ORDER) if index not in by_lop]
    print(f"derived {len(measured)} opcodes, missing {missing}")
    print(f"NEWTABLE 0x{measured['NEWTABLE']['byte']:02X}  "
          f"SETLIST 0x{measured['SETLIST']['byte']:02X}  "
          f"NEWCLOSURE 0x{measured['NEWCLOSURE']['byte']:02X}  "
          f"CONCAT 0x{measured['CONCAT']['byte']:02X}")


def load_widths():
    path = os.path.join(os.environ.get("TEMP", ""), "opencode", "luau", "tab_w.bin")
    if not os.path.exists(path):
        return None
    data = open(path, "rb").read()
    if len(data) != 256:
        return None
    return data


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IMAGE)
