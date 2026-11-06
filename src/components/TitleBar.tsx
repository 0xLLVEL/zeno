import { useEffect, useState } from "react";
import { useZeno } from "../store";

async function windowApi() {
  const mod = await import("@tauri-apps/api/window");
  return mod.getCurrentWindow();
}

export function TitleBar({ onExecute }: { onExecute: () => void }) {
  const { running, attached, statusMessage } = useZeno();
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const w = await windowApi();
        setMaximized(await w.isMaximized());
        unlisten = await w.onResized(async () => setMaximized(await w.isMaximized()));
      } catch {
        /* browser preview */
      }
    })();
    return () => unlisten?.();
  }, []);

  const ctl = async (action: "min" | "max" | "close") => {
    try {
      const w = await windowApi();
      if (action === "min") await w.minimize();
      else if (action === "max") await w.toggleMaximize();
      else await w.close();
    } catch {
      /* preview */
    }
  };

  return (
    <header className="titlebar" data-tauri-drag-region>
      <div className="tb-left" data-tauri-drag-region>
        <span className="tb-logo">ZENO</span>
        <span className="tb-sep">/</span>
        <span className="tb-state">
          <i className={`dot ${attached ? "on" : "off"}`} />
          {attached ? "attached" : "idle"}
        </span>
        <span className="tb-msg">{statusMessage}</span>
      </div>

      <div className="tb-center" data-tauri-drag-region>
        <button
          className={`run-btn ${running ? "busy" : ""}`}
          onClick={onExecute}
          disabled={running}
          title="Execute (Ctrl+Enter)"
        >
          {running ? (
            <>
              <span className="spinner" /> running
            </>
          ) : (
            <>
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                <path d="M8 5v14l11-7z" />
              </svg>
              execute
            </>
          )}
        </button>
        <kbd>ctrl ↵</kbd>
      </div>

      <div className="tb-right">
        <button className="win-btn" onClick={() => ctl("min")} title="minimize">
          <svg viewBox="0 0 10 10" width="10" height="10"><path d="M2 5h6" stroke="currentColor" /></svg>
        </button>
        <button className="win-btn" onClick={() => ctl("max")} title="maximize">
          <svg viewBox="0 0 10 10" width="10" height="10">
            {maximized ? (
              <path d="M2 4h4v4H2z M4 2h4v4" fill="none" stroke="currentColor" />
            ) : (
              <rect x="2" y="2" width="6" height="6" fill="none" stroke="currentColor" />
            )}
          </svg>
        </button>
        <button className="win-btn close" onClick={() => ctl("close")} title="close">
          <svg viewBox="0 0 10 10" width="10" height="10">
            <path d="M2 2l6 6M8 2l-6 6" stroke="currentColor" />
          </svg>
        </button>
      </div>
    </header>
  );
}
