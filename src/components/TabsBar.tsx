import { useZeno } from "../store";

export function TabsBar({ onOpenFile }: { onOpenFile: () => void }) {
  const { tabs, activeTabId, setActiveTab, closeTab, addTab } = useZeno();

  return (
    <div className="tabs-bar">
      <div className="tabs-scroll">
        {tabs.map((t) => (
          <div
            key={t.id}
            className={`tab ${t.id === activeTabId ? "active" : ""}`}
            onClick={() => setActiveTab(t.id)}
            onAuxClick={(e) => e.button === 1 && closeTab(t.id)}
          >
            <span className="tab-dot" data-dirty={t.dirty} />
            <span className="tab-name">{t.name}</span>
            <button
              className="tab-close"
              onClick={(e) => {
                e.stopPropagation();
                closeTab(t.id);
              }}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      <button className="tab-action" title="new tab" onClick={() => addTab()}>
        +
      </button>
      <button className="tab-action" title="open file" onClick={onOpenFile}>
        ⌸
      </button>
    </div>
  );
}
