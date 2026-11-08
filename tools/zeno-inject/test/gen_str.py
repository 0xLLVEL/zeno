"""Emit pad scripts whose bytecode size is controlled byte-for-byte.

A single string literal grows the blob one byte per character, so this can land
on an exact size instead of the 17-byte steps a statement chain gives.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
COMPILER = r"C:\Users\ezan\AppData\Local\Temp\opencode\luau\luaucomp.exe"
OPMAP = os.path.join(HERE, "opmap_client.bin")


def source(k):
    return 'local s = "' + "A" * k + '"\nreturn #s\n'


def main():
    targets = [int(x) for x in sys.argv[1:]]
    tmp_src = os.path.join(HERE, "_pad.lua")
    tmp_raw = os.path.join(HERE, "_pad.raw")
    env = dict(os.environ)
    env["ZENO_OPMAP"] = OPMAP

    def measure(k):
        with open(tmp_src, "w", encoding="utf-8", newline="\n") as f:
            f.write(source(k))
        proc = subprocess.run([COMPILER, tmp_src, tmp_raw, "--O0"],
                              capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise SystemExit(proc.stderr)
        return os.path.getsize(tmp_raw)

    base = measure(0)
    print(f"base bytecode {base}")
    for target in targets:
        k = target - base
        if k < 0:
            print(f"target {target} below base")
            continue
        got = measure(k)
        name = os.path.join(HERE, f"t_sz{got}.lua")
        with open(name, "w", encoding="utf-8", newline="\n") as f:
            f.write(source(k))
        print(f"target {target:4d} -> literal {k:4d} bytecode {got} {os.path.basename(name)}")

    for leftover in (tmp_src, tmp_raw):
        if os.path.exists(leftover):
            os.remove(leftover)


if __name__ == "__main__":
    main()
