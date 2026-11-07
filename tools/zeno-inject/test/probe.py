"""Hand-assembled semantic probes for the f0ea client opcode space.

The handler table tells us which handler a canonical byte reaches, and static
matching guesses which Luau opcode that handler implements. Neither is proof.
This builds a blob that runs one candidate byte per probe with controlled
operands and returns every result, so the opcode's meaning is read off the
output instead of inferred from code shape.

Layout: results land in r0..rN-1 and the proto returns all of them at once, so
one hijack resolves a whole family. Inputs live at r40.. and up, out of the way
of the result window.

usage: python probe.py <out.bc> [family]
"""

import struct
import sys

from gen_blob import build, wv

RESULT = 0          # first result register
IN_A = 40           # first input register
IN_B = 41
IN_C = 42
IN_D = 43

NUM_40 = 0
NUM_2 = 1
NUM_100 = 2
NUM_1 = 3
STR_AB = 4
STR_CD = 5
TRUE_ = 6
FALSE_ = 7
NIL = 8

CONSTS = [
    (2, struct.pack('<d', 40.0)),
    (2, struct.pack('<d', 2.0)),
    (2, struct.pack('<d', 100.0)),
    (2, struct.pack('<d', 1.0)),
    (3, wv(1)),
    (3, wv(2)),
    (1, bytes([1])),
    (1, bytes([0])),
]
STRINGS = [b'ab', b'cd']


def abc(op, a, b, c):
    return op | (a << 8) | (b << 16) | (c << 24)


def ad(op, a, d):
    return op | (a << 8) | ((d & 0xFFFF) << 16)


def setup():
    """Load the shared inputs once, ahead of the probe window."""
    return [
        (0x86, [abc(0x86, IN_A, 0, 0), NUM_40]),
        (0x86, [abc(0x86, IN_B, 0, 0), NUM_2]),
        (0x86, [abc(0x86, IN_C, 0, 0), NUM_100]),
        (0x86, [abc(0x86, IN_D, 0, 0), NUM_1]),
        (0x86, [abc(0x86, 44, 0, 0), STR_AB]),
        (0x86, [abc(0x86, 45, 0, 0), STR_CD]),
        (0x86, [abc(0x86, 46, 0, 0), TRUE_]),
        (0x86, [abc(0x86, 47, 0, 0), FALSE_]),
    ]


# Each entry: (label, byte, words-for-the-instruction, expected-if-known).
# `abc` uses registers, `aux` marks a second word holding a constant index.
PROBES = [
    # Arithmetic with a register right-hand side: 40 op 2.
    ('ADD?', 0x43, [abc(0x43, RESULT + 0, IN_A, IN_B)], '42'),
    ('SUB?', 0x26, [abc(0x26, RESULT + 1, IN_A, IN_B)], '38'),
    ('MUL?', 0x09, [abc(0x09, RESULT + 2, IN_A, IN_B)], '80'),
    ('DIV?', 0xEC, [abc(0xEC, RESULT + 3, IN_A, IN_B)], '20'),
    ('MOD?', 0xCF, [abc(0xCF, RESULT + 4, IN_A, IN_B)], '0'),
    ('POW?', 0xB2, [abc(0xB2, RESULT + 5, IN_A, IN_B)], '1600'),
    ('IDIV?', 0xB6, [abc(0xB6, RESULT + 6, IN_A, IN_B)], '20'),
    # Arithmetic with a constant right-hand side: 40 op 100.
    ('ADDK?', 0x95, [abc(0x95, RESULT + 7, IN_A, 0), NUM_100], '140'),
    ('SUBK?', 0xF5, [abc(0xF5, RESULT + 8, IN_A, 0), NUM_100], '-60'),
    ('MULK?', 0x5B, [abc(0x5B, RESULT + 9, IN_A, 0), NUM_100], '4000'),
    ('DIVK?', 0x3E, [abc(0x3E, RESULT + 10, IN_A, 0), NUM_100], '0.4'),
    ('MODK?', 0x21, [abc(0x21, RESULT + 11, IN_A, 0), NUM_100], '40'),
    ('POWK?', 0x04, [abc(0x04, RESULT + 12, IN_A, 0), NUM_2], '1600'),
    ('DIVRK?', 0xD8, [abc(0xD8, RESULT + 13, IN_A, 0), NUM_100], '2.5'),
    # Boolean select: 40 and/or 2 -> 2 and 40 respectively.
    ('AND?', 0xCA, [abc(0xCA, RESULT + 14, IN_A, IN_B)], '2'),
    ('OR?', 0xE7, [abc(0xE7, RESULT + 15, IN_A, IN_B)], '40'),
    ('ANDK?', 0x90, [abc(0x90, RESULT + 16, IN_A, 0), NUM_2], '2'),
    ('ORK?', 0xAD, [abc(0xAD, RESULT + 17, IN_A, 0), NUM_2], '40'),
    # Unary and copy.
    ('NOT?', 0x56, [abc(0x56, RESULT + 18, 46, 0)], 'false'),
    ('MINUS?', 0x39, [abc(0x39, RESULT + 19, IN_A, 0)], '-40'),
    ('LENGTH?', 0x1C, [abc(0x1C, RESULT + 20, 44, 0)], '2'),
    ('CONCAT?', 0xD3, [abc(0xD3, RESULT + 21, 44, 45)], 'abcd'),
    ('MOVE?', 0x52, [abc(0x52, RESULT + 22, IN_A, 0)], '40'),
    ('LOADNIL?', 0xC6, [abc(0xC6, RESULT + 23, 0, 0)], 'nil'),
    ('LOADB?', 0xA9, [abc(0xA9, RESULT + 24, 0, 1)], 'true'),
    # Control check: proves constant encoding and the result window.
    ('LOADKX', 0x86, [abc(0x86, RESULT + 25, 0, 0), NUM_2], '2'),
]


def build_probe(path, probes):
    words = []
    for _, seq in setup():
        words.extend(seq)
    for _, _, seq, _ in probes:
        words.extend(seq)
    words.append(abc(0x82, RESULT, len(probes) + 1, 0))

    build(words, STRINGS, CONSTS, path, maxstack=IN_A + 8)


def main(argv):
    path = argv[1] if len(argv) > 1 else 'probe_family.bc'
    build_probe(path, PROBES)
    print(f'--- {len(PROBES)} probes, result registers {RESULT}..{RESULT + len(PROBES) - 1}')
    for index, (label, byte, _, expect) in enumerate(PROBES):
        print(f'  r{RESULT + index:<3} byte {byte:02X} {label:<10} expect {expect}')


if __name__ == '__main__':
    main(sys.argv)
