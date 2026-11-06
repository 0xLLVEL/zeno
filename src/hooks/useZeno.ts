import { useEffect, useRef } from "react";
import { api } from "../lib/api";
import { useZeno } from "../store";

const POLL_MS = 900;

export function useOutputPump() {
  const log = useZeno((s) => s.log);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    let timer: number | undefined;

    const tick = async () => {
      if (!alive.current) return;
      try {
        const lines = await api.drainOutput();
        for (const raw of lines) {
          const line = raw.replace(/\r$/, "");
          if (!line) continue;
          const level = line.startsWith("[error]")
            ? "error"
            : line.startsWith("[warn]")
              ? "warn"
              : line.startsWith("[zeno]")
                ? "info"
                : "out";
          log(level, line.replace(/^\[\w+\]\s?/, ""));
        }
      } catch {
        /* pipe not up yet */
      }
      timer = window.setTimeout(tick, POLL_MS);
    };

    tick();
    return () => {
      alive.current = false;
      if (timer) window.clearTimeout(timer);
    };
  }, [log]);
}

export function useStatusPoller() {
  const setAttached = useZeno((s) => s.setAttached);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const st = await api.status();
        if (!alive) return;
        setAttached(st.attached && st.injected, st.message);
      } catch {
        /* noop */
      }
      if (alive) window.setTimeout(tick, 1500);
    };
    tick();
    return () => {
      alive = false;
    };
  }, [setAttached]);
}
