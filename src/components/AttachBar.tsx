import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useZeno } from "../store";
import type { ProcessInfo } from "../types";

export function AttachBar() {
  const { attached, statusMessage, settings, setAttached, log } = useZeno();
  const [procs, setProcs] = useState<ProcessInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);

  const scan = async () => {
    const list = await api.listProcesses();
    setProcs(list);
    if (list.length === 1 && settings.autoAttach && !attached) {
      void attach(list[0].pid);
    }
    return list;
  };

  useEffect(() => {
    let alive = true;
    const run = async () => {
      const list = await api.listProcesses();
      if (!alive) return;
      setProcs(list);
      if (list.length === 1 && settings.autoAttach && !useZeno.getState().attached) {
        void attach(list[0].pid);
      }
    };
    run();
    const id = window.setInterval(run, 4000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.autoAttach]);

  const attach = async (pid: number) => {
    setBusy(true);
    try {
      const st = await api.attach(pid, settings.injectionMethod);
      setAttached(st.attached && st.injected, st.message);
      log(st.attached && st.injected ? "ok" : "error", st.message);
      if (st.attached && st.injected) setOpen(false);
    } catch (e) {
      log("error", `attach failed: ${String(e)}`);
      setAttached(false, "attach failed");
    } finally {
      setBusy(false);
    }
  };

  const detach = async () => {
    await api.detach();
    setAttached(false, "detached");
    log("warn", "detached from process");
  };

  return (
    <div className="attach-bar">
      <div className={`dot ${attached ? "on" : "off"}`} />
      <span className="attach-label" title={statusMessage}>
        {attached ? (statusMessage || "attached") : "not attached"}
      </span>

      <div className="attach-menu-wrap">
        <button
          className={`btn ${attached ? "ghost" : "primary"}`}
          disabled={busy}
          onClick={() => (attached ? detach() : (scan(), setOpen((v) => !v)))}
        >
          {busy ? "working…" : attached ? "detach" : "attach"}
        </button>

        {open && !attached && (
          <div className="dropdown" onMouseLeave={() => setOpen(false)}>
            <div className="dropdown-head">
              <span>roblox processes</span>
              <button className="mini" onClick={scan}>
                rescan
              </button>
            </div>
            {procs.length === 0 && (
              <div className="dropdown-empty">no roblox client found — launch a game</div>
            )}
            {procs.map((p) => (
              <button key={p.pid} className="dropdown-item" onClick={() => attach(p.pid)}>
                <span className="pid">{p.pid}</span>
                <span className="pname">{p.name}</span>
                <span className="pver">{p.version}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
