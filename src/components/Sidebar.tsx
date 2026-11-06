import { useZeno } from "../store";
import { AttachBar } from "./AttachBar";

type Icon =
  | "editor"
  | "hub"
  | "console"
  | "settings";

const NAV: { id: Icon; label: string; path: string }[] = [
  {
    id: "editor",
    label: "Editor",
    path: "M4 5h16M4 10h10M4 15h14M4 20h8",
  },
  {
    id: "hub",
    label: "Hub",
    path: "M4 6h6v6H4zM14 6h6v6h-6zM4 16h6v4H4zM14 16h6v4h-6z",
  },
  {
    id: "console",
    label: "Console",
    path: "M4 5h16v14H4zM7 9l3 3-3 3M12 15h4",
  },
  {
    id: "settings",
    label: "Settings",
    path: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM4 12h2M18 12h2M12 4v2M12 18v2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M17.7 6.3l-1.4 1.4M7.7 16.3l-1.4 1.4",
  },
];

export function Sidebar() {
  const { sidebar, setSidebar } = useZeno();

  return (
    <aside className="sidebar">
      <div className="brand" title="Zeno">
        <span className="brand-mark">Z</span>
      </div>

      <nav className="nav">
        {NAV.map((n) => (
          <button
            key={n.id}
            className={`nav-btn ${sidebar === n.id ? "active" : ""}`}
            onClick={() => setSidebar(n.id)}
            title={n.label}
          >
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d={n.path} />
            </svg>
            <span className="nav-label">{n.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <AttachBar />
      </div>
    </aside>
  );
}
