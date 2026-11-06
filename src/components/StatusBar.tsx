import { useEffect } from "react";
import { useZeno } from "../store";

export function StatusBar() {
  const { attached, running, tabs, statusMessage, logs } = useZeno();

  return (
    <footer className="statusbar">
      <span className={`sb-item state ${attached ? "ok" : "bad"}`}>
        <i className={`dot ${attached ? "on" : "off"}`} />
        {attached ? "attached" : "detached"}
      </span>
      <span className="sb-item">{running ? "executing…" : "idle"}</span>
      <span className="sb-item">{tabs.length} tab{tabs.length === 1 ? "" : "s"}</span>
      <span className="sb-item">{logs.length} log lines</span>
      <span className="sb-spacer" />
      <span className="sb-item dim">{statusMessage}</span>
      <span className="sb-item accent">zeno v1.0.0</span>
    </footer>
  );
}

export function useKeyboardShortcuts(onExecute: () => void) {
  const { addTab } = useZeno();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key === "Enter") {
        e.preventDefault();
        onExecute();
      } else if (mod && e.key.toLowerCase() === "t") {
        e.preventDefault();
        addTab();
      }
    };
    const onExec = () => onExecute();
    window.addEventListener("keydown", onKey);
    document.addEventListener("zeno:execute", onExec as EventListener);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("zeno:execute", onExec as EventListener);
    };
  }, [onExecute, addTab]);
}
