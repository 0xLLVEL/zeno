import { useEffect, useMemo, useRef, useState } from "react";
import { useZeno } from "../store";
import { api } from "../lib/api";
import type { LogLevel } from "../types";

const time = (t: number) =>
  new Date(t).toLocaleTimeString(undefined, {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

export function ConsolePane() {
  const { logs, clearLogs, log } = useZeno();
  const [filter, setFilter] = useState<LogLevel | "all">("all");
  const [query, setQuery] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const [autoscroll, setAutoscroll] = useState(true);

  const shown = useMemo(
    () =>
      logs.filter(
        (l) =>
          (filter === "all" || l.level === filter || (filter === "out" && l.level === "out")) &&
          (!query || l.text.toLowerCase().includes(query.toLowerCase())),
      ),
    [logs, filter, query],
  );

  useEffect(() => {
    if (autoscroll) bottomRef.current?.scrollIntoView({ block: "end" });
  }, [shown.length, autoscroll]);

  return (
    <div className="pane console-pane">
      <div className="console-head">
        <div className="console-filters">
          {(["all", "info", "ok", "warn", "error", "out"] as const).map((f) => (
            <button
              key={f}
              className={`chip ${filter === f ? "on" : ""} lv-${f}`}
              onClick={() => setFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>
        <input
          className="console-search"
          placeholder="filter output…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <label className="toggle-inline">
          <input
            type="checkbox"
            checked={autoscroll}
            onChange={(e) => setAutoscroll(e.target.checked)}
          />
          follow
        </label>
        <button className="mini" onClick={clearLogs}>
          clear
        </button>
      </div>

      <div className="console-body">
        {shown.length === 0 && (
          <div className="console-empty">no output yet — execute a script to see logs</div>
        )}
        {shown.map((l) => (
          <div key={l.id} className={`log-line lv-${l.level}`}>
            <span className="log-time">{time(l.time)}</span>
            <span className="log-badge">{l.level}</span>
            <span className="log-text">{l.text}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <form
        className="console-input"
        onSubmit={async (e) => {
          e.preventDefault();
          const field = e.currentTarget.elements.namedItem("cmd") as HTMLInputElement;
          const input = field.value;
          if (!input.trim()) return;
          log("info", `> ${input}`);
          field.value = "";
          try {
            const res = await api.execute(input);
            if (!res.ok) log("error", res.error ?? "execution failed");
          } catch (err) {
            log("error", String(err));
          }
        }}
      >
        <span className="prompt">›</span>
        <input name="cmd" placeholder="run a line in roblox…" autoComplete="off" spellCheck={false} />
      </form>
    </div>
  );
}
