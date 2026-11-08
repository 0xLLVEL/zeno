"""Emit pad scripts whose compiled bytecode lands near a target size.

Separates 'this construct breaks the loader' from 'chunks past N bytes break
the loader' by growing a trivial script one statement at a time.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
COMPILER = r"C:\Users\ezan\AppData\Local\Temp\opencode\luau\luaucomp.exe"
OPMAP = os.path.join(HERE, "opmap_client.bin")


def source(n):
    lines = ["local acc = 0"]
    for i in range(n):
        lines.append(f"acc = acc + {i}")
    lines.append("return acc")
    return "\n".join(lines) + "\n"


def main():
    targets = [int(x) for x in sys.argv[1:]]
    tmp_src = os.path.join(HERE, "_pad.lua")
    tmp_raw = os.path.join(HERE, "_pad.raw")
    env = dict(os.environ)
    env["ZENO_OPMAP"] = OPMAP
    cache = {}

    def measure(n):
        if n not in cache:
            with open(tmp_src, "w", encoding="utf-8", newline="\n") as f:
                f.write(source(n))
            proc = subprocess.run([COMPILER, tmp_src, tmp_raw, "--O0"],
                                  capture_output=True, text=True, env=env)
            if proc.returncode != 0:
                raise SystemExit(proc.stderr)
            cache[n] = os.path.getsize(tmp_raw)
        return cache[n]

    for target in targets:
        lo, hi = 1, 8000
        while lo < hi:
            mid = (lo + hi) // 2
            if measure(mid) < target:
                lo = mid + 1
            else:
                hi = mid
        n = lo
        name = os.path.join(HERE, f"t_pad{measure(n)}.lua")
        with open(name, "w", encoding="utf-8", newline="\n") as f:
            f.write(source(n))
        print(f"target {target:4d} -> statements {n:4d} bytecode {measure(n)} {os.path.basename(name)}")

    for leftover in (tmp_src, tmp_raw):
        if os.path.exists(leftover):
            os.remove(leftover)


if __name__ == "__main__":
    main()
