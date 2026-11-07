"""Build the 256-byte LOP -> canonical opcode table the compiler reads.

usage: mkopmap.py <map.json> <out.bin>

The JSON is keyed by Luau LOP name (NOP, LOADK, ...) with a byte value; the
output is indexed by LOP number, which is what BytecodeBuilder's opmap_byte
expects. Unmapped slots stay at their identity value so a partially filled map
still produces a usable table.
"""

import json
import sys

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


def main(argv):
    if len(argv) < 3:
        raise SystemExit("usage: mkopmap.py <map.json> <out.bin>")
    mapping = json.load(open(argv[1], "r", encoding="utf-8"))
    table = bytearray(range(256))
    missing = []
    for index, name in enumerate(LOP_ORDER):
        value = mapping.get(name)
        if value is None:
            missing.append(name)
            continue
        table[index] = int(value, 0) if isinstance(value, str) else int(value)
    open(argv[2], "wb").write(bytes(table))
    print(f"wrote {argv[2]}: {len(LOP_ORDER) - len(missing)}/{len(LOP_ORDER)} mapped")
    if missing:
        print("unmapped:", " ".join(missing))


if __name__ == "__main__":
    main(sys.argv)
