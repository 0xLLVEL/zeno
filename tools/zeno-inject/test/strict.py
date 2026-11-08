import sys, os

MAGIC = bytes.fromhex('527a104a5b3209e0')

def rv(d, o):
    v = 0; s = 0
    while True:
        b = d[o]; o += 1
        v |= (b & 0x7f) << s
        if b < 0x80:
            return v, o
        s += 7

def parse(path):
    d = open(path, 'rb').read()
    assert d[:8] == MAGIC, 'magic'
    o = 8
    ver = d[o]; tv = d[o+1]; o += 2
    n, o = rv(d, o)
    for _ in range(n):
        ln, o = rv(d, o); o += ln
    if tv == 3:
        while d[o] != 0:
            o += 1
            _, o = rv(d, o)
        o += 1
    np, o = rv(d, o)
    for _ in range(np):
        size, o = rv(d, o)
        o += size
    return ver, tv, n, np, o, len(d)

for path in sorted(sys.argv[1:]):
    try:
        ver, tv, n, np_, end, total = parse(path)
        flag = 'OK' if end == total else f'MISMATCH trailing {total-end}'
        print(f'{os.path.basename(path):22s} strings {n:3d} protos {np_} end 0x{end:X} len 0x{total:X} {flag}')
    except Exception as e:
        print(f'{os.path.basename(path):22s} ERROR {e}')
