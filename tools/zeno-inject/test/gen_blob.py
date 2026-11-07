"""Luau bytecode blob generator for the f0ea client build (0.746, version-f0ea5da9412f4e35).

Everything here is measured from the running client, not assumed:

- Canonical opcode index -> runtime dispatch byte goes through the substitution
  table at image RVA 0x735B280. The canonical indices below were read out of it.
- The container needs the 8-byte magic, otherwise LuaVMLoad rejects the blob.
- String table index 0 is reserved by the client (readString subtracts 1), so the
  first real string lives at index 1.
- LOADK's aux word is the constant table index, not the string table index.
- Constant tags come from the tag switch at RVA 0x26657A0:
  1 boolean, 2 number, 3 string, 4 import, 5 table, 6 closure, 7 vector,
  8 table-with-constants, 9 integer, 10 class shape, 11 vectord.
"""

import struct
import sys

MAGIC = bytes.fromhex('527A104A5B3209E0')

LOADK = 0x86    # two words: opcode+A, then constant index
LOADN = 0x8C    # A, signed 16-bit D
RETURN = 0x82   # A, B = results + 1


def wv(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build(words, strings, consts, out_path, maxstack=3):
    body = bytearray()
    body += bytes([maxstack, 0, 0, 0, 0])
    body += wv(0)                      # typesize
    body += wv(len(words))
    for word in words:
        body += struct.pack('<I', word)
    body += wv(len(consts))
    for tag, payload in consts:
        body += bytes([tag])
        body += payload
    body += wv(0)                      # sizep
    body += wv(0)                      # linedefined
    body += wv(0)                      # debugname
    body += bytes([0])                 # lineinfo
    body += bytes([0])                 # debuginfo
    body += wv(0)                      # feedbackvecsize

    blob = bytearray()
    blob += bytes([14, 3])             # version 14, typesversion 3
    blob += wv(len(strings))
    for text in strings:
        blob += wv(len(text)) + text
    blob += bytes([0])                 # userdata remap terminator
    blob += wv(1)                      # protoCount
    blob += wv(len(body))
    blob += body
    blob += wv(0)                      # main proto id

    with open(out_path, 'wb') as handle:
        handle.write(MAGIC + bytes(blob))

    print(f'{out_path}: {len(blob) + 8} bytes, sizecode {len(words)}, sizek {len(consts)}')
    for index, word in enumerate(words):
        print(f'  word{index}: {word:08X}')


def tstring(index):
    return (3, wv(index))


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else '.'

    build(
        [LOADN | (0 << 8) | (4 << 16),
         RETURN | (0 << 8) | (2 << 16)],
        [], [],
        f'{out_dir}/ret4.bc',
        maxstack=2,
    )

    text = b'zeno-alive'
    build(
        [LOADK | (0 << 8), 0,
         LOADN | (1 << 8) | (4 << 16),
         RETURN | (0 << 8) | (3 << 16)],
        [text], [tstring(1)],
        f'{out_dir}/alive5.bc',
        maxstack=3,
    )
