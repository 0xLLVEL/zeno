"""Compile a .lua file into a zeno-loadable blob.

Pipeline:
  1. luaucomp.exe compiles source -> canonical Luau bytecode (version 14,
     typesversion 3). The compiler's opcode map MUST stay identity here: the
     client's loader rewrites canonical -> dispatch bytes itself, so feeding it
     pre-mapped bytecode double-maps every opcode and kills the VM.
  2. The 8-byte container magic is prepended, which is what LuaVMLoad strips
     before handing the payload to the protected parser.

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

# canonical opcode -> width in 32-bit words, for sanity checking a blob
WIDTH = {}


def compile_source(src_path, out_path):
    env = dict(os.environ)
    env.pop("ZENO_OPMAP", None)  # identity: canonical bytecode out
    raw = out_path + ".raw"
    proc = subprocess.run([COMPILER, src_path, raw], capture_output=True, text=True, env=env)
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
