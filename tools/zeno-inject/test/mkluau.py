"""Compile a .lua file into a zeno-loadable blob.

Pipeline:
  1. luaucomp.exe compiles source -> bytecode (version 14, typesversion 3).
     The compiler is driven with ZENO_OPMAP pointing at `opmap_client.bin`,
     which maps each LOP number to the CLIENT's canonical opcode byte. That
     byte is what the loader's own canonical->dispatch table (rva 0x735B280)
     is indexed by. Emitting upstream LOP bytes instead makes the loader
     rewrite every instruction to a byte the interpreter does not know, and
     the dispatch guard fastfails with `int 0x29`.
  2. The 8-byte container magic is prepended, which is what LuaVMLoad strips
     before handing the payload to the protected parser.

`opmap_client.bin` is rebuilt from `opmap_guess.json` by `build_opmap()`
below, so it never goes stale relative to the measured map.

Usage:
    python mkluau.py <in.lua> <out.bc>
    python mkluau.py --check <blob.bc>
"""

import os
import struct
import subprocess
import sys

MAGIC = bytes([0x52, 0x7A, 0x10, 0x4A, 0x5B, 0x32, 0x09, 0xE0])
COMPILER = r"C:\Users\ezan\AppData\Local\Temp\opencode\luau\luaucomp.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
GUESS = os.path.join(HERE, "opmap_guess.json")
OPMAP = os.path.join(HERE, "opmap_client.bin")

# LOP number -> name, in the compiler's own enum order.
LOP_ORDER = [
    "NOP", "BREAK", "LOADNIL", "LOADB", "LOADN", "LOADK", "MOVE", "GETGLOBAL",
    "SETGLOBAL", "GETUPVAL", "SETUPVAL", "CLOSEUPVALS", "GETIMPORT", "GETTABLE",
    "SETTABLE", "GETTABLEKS", "SETTABLEKS", "GETTABLEN", "SETTABLEN",
    "NEWCLOSURE", "NAMECALL", "CALL", "RETURN", "JUMP", "JUMPBACK", "JUMPIF",
    "JUMPIFNOT", "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ",
    "JUMPIFNOTLE", "JUMPIFNOTLT", "ADD", "SUB", "MUL", "DIV", "MOD", "POW",
    "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "AND", "OR", "ANDK", "ORK",
    "CONCAT", "NOT", "MINUS", "LENGTH", "NEWTABLE", "DUPTABLE", "SETLIST",
    "FORNPREP", "FORNLOOP", "FORGLOOP", "FORGPREP_INEXT", "FASTCALL3",
    "FORGPREP_NEXT", "NATIVECALL", "GETVARARGS", "DUPCLOSURE", "PREPVARARGS",
    "LOADKX", "JUMPX", "FASTCALL", "COVERAGE", "CAPTURE", "SUBRK", "DIVRK",
    "FASTCALL1", "FASTCALL2", "FASTCALL2K", "FORGPREP", "JUMPXEQKNIL",
    "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS", "IDIV", "IDIVK", "GETUDATAKS",
    "SETUDATAKS", "NAMECALLUDATA", "NEWCLASSMEMBER", "CALLFB", "CMPPROTO",
    "FASTPCALL", "NEWCLASS", "CONSTRUCT", "FINCONSTRUCT", "GETPRIVATEFIELD",
    "SETPRIVATEFIELD",
]


def build_opmap():
    """Compose the client's canonical opcode table from the measured map.

    `opmap_guess.json` is keyed by LOP name and holds the byte the client's
    loader expects in the blob. The compiler reads a 256-byte table indexed by
    LOP number, so reorder it here.

    Every byte in the file is now derived from the client image, not guessed:
    the loader's rewrite table (rva 0x735B280) maps a canonical byte to the
    interpreter's dispatch byte, and `SC` (rva 0x735B380, indexed by dispatch
    byte) yields the LOP number the interpreter implements for it. Inverting
    `SC[T[c]]` therefore names all 94 implemented opcodes exactly. The only
    upstream LOP with no handler is CAPTURE, which is analysis-only and never
    emitted into a loadable chunk.
    """
    import json

    measured = json.load(open(GUESS, "r", encoding="utf-8"))
    table = bytearray(range(256))
    for index, name in enumerate(LOP_ORDER):
        entry = measured.get(name)
        if entry is not None:
            table[index] = entry["byte"]
    with open(OPMAP, "wb") as f:
        f.write(bytes(table))
    return OPMAP


def compile_source(src_path, out_path):
    build_opmap()
    env = dict(os.environ)
    env["ZENO_OPMAP"] = OPMAP
    raw = out_path + ".raw"
    command = [COMPILER, src_path, raw]
    if env.get("ZENO_O0"):
        # -O0 keeps global reads as GETGLOBAL instead of GETIMPORT. An import
        # constant has to resolve against the chunk's environment when it runs,
        # and an unresolvable one raises; a GETGLOBAL on a missing key is just
        # nil. Use it whenever the script probes a host's globals.
        command.append("--O0")
    proc = subprocess.run(command, capture_output=True, text=True, env=env)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        raise SystemExit(f"compile failed: {proc.returncode}")
    body = open(raw, "rb").read()
    os.remove(raw)
    if len(body) < 2 or body[0] != 14:
        raise SystemExit(f"unexpected bytecode header {body[:2].hex()}")
    blob = MAGIC + body
    with open(out_path, "wb") as f:
        f.write(blob)
    print(f"{out_path}: {len(blob)} bytes (bytecode {len(body)})")


def read_varint(data, off):
    value = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, off
        shift += 7


def check(path):
    data = open(path, "rb").read()
    if data[:8] != MAGIC:
        raise SystemExit("missing container magic")
    off = 8
    version = data[off]
    typesversion = data[off + 1]
    off += 2
    strings, off = read_varint(data, off)
    table = []
    for _ in range(strings):
        n, off = read_varint(data, off)
        table.append(data[off:off + n])
        off += n
    if typesversion == 3:
        while data[off] != 0:
            off += 1
            _, off = read_varint(data, off)
        off += 1
    protos, off = read_varint(data, off)
    print(f"version {version} typesversion {typesversion} strings {strings} protos {protos}")
    for i in range(protos):
        size, off = read_varint(data, off)
        start = off
        maxstack, numparams, nups, is_vararg, flags = data[off:off + 5]
        off += 5
        typesize, off = read_varint(data, off)
        off += typesize
        sizecode, off = read_varint(data, off)
        words = struct.unpack_from(f"<{sizecode}I", data, off)
        off += 4 * sizecode
        print(f"proto {i}: size {size} stack {maxstack} params {numparams} nups {nups} "
              f"vararg {is_vararg} flags {flags} code {sizecode}")
        print("  " + " ".join(f"{w:08X}" for w in words))
        for name, text in zip(range(strings), table):
            print(f"  s[{name}] {text!r}")
        off = start + size
    print(f"end offset {off} / {len(data)}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        check(sys.argv[2])
    elif len(sys.argv) == 3:
        compile_source(sys.argv[1], sys.argv[2])
    else:
        raise SystemExit(__doc__)
