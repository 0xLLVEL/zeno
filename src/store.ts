import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { LogEntry, LogLevel, ScriptTab, Settings } from "./types";
import { DEFAULT_SOURCE } from "./types";

let logSeq = 1;
let tabSeq = 1;

const uid = () => `t${tabSeq++}_${Date.now().toString(36)}`;

export interface ZenoState {
  tabs: ScriptTab[];
  activeTabId: string;
  logs: LogEntry[];
  running: boolean;
  attached: boolean;
  statusMessage: string;
  settings: Settings;
  sidebar: "editor" | "hub" | "console" | "settings";

  addTab: (name?: string, source?: string) => void;
  closeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  updateSource: (id: string, source: string) => void;
  renameTab: (id: string, name: string) => void;

  log: (level: LogLevel, text: string) => void;
  clearLogs: () => void;

  setRunning: (v: boolean) => void;
  setAttached: (v: boolean, msg?: string) => void;
  patchSettings: (p: Partial<Settings>) => void;
  setSidebar: (s: ZenoState["sidebar"]) => void;
}

const defaultSettings: Settings = {
  autoAttach: true,
  editorFontSize: 14,
  editorMinimap: true,
  wrapLines: false,
  autoExecute: false,
  consoleMaxLines: 2000,
  accent: "#7c5cff",
  injectionMethod: "loadlibrary",
};

export const useZeno = create<ZenoState>()(
  persist(
    (set, get) => ({
      tabs: [{ id: "t0", name: "untitled.lua", source: DEFAULT_SOURCE, dirty: false }],
      activeTabId: "t0",
      logs: [],
      running: false,
      attached: false,
      statusMessage: "idle — waiting for roblox",
      settings: defaultSettings,
      sidebar: "editor",

      addTab: (name, source) => {
        const id = uid();
        const tab: ScriptTab = {
          id,
          name: name ?? `script${tabSeq}.lua`,
          source: source ?? DEFAULT_SOURCE,
          dirty: false,
        };
        set((s) => ({ tabs: [...s.tabs, tab], activeTabId: id }));
      },

      closeTab: (id) =>
        set((s) => {
          if (s.tabs.length === 1) return s;
          const idx = s.tabs.findIndex((t) => t.id === id);
          const tabs = s.tabs.filter((t) => t.id !== id);
          const activeTabId =
            s.activeTabId === id ? tabs[Math.max(0, idx - 1)].id : s.activeTabId;
          return { tabs, activeTabId };
        }),

      setActiveTab: (id) => set({ activeTabId: id }),

      updateSource: (id, source) =>
        set((s) => ({
          tabs: s.tabs.map((t) => (t.id === id ? { ...t, source, dirty: true } : t)),
        })),

      renameTab: (id, name) =>
        set((s) => ({ tabs: s.tabs.map((t) => (t.id === id ? { ...t, name } : t)) })),

      log: (level, text) =>
        set((s) => {
          const entry: LogEntry = { id: logSeq++, level, text, time: Date.now() };
          const logs = [...s.logs, entry];
          const cap = s.settings.consoleMaxLines;
          return { logs: logs.length > cap ? logs.slice(logs.length - cap) : logs };
        }),

      clearLogs: () => set({ logs: [] }),

      setRunning: (v) => set({ running: v }),

      setAttached: (v, msg) =>
        set({ attached: v, statusMessage: msg ?? (v ? "attached" : "detached") }),

      patchSettings: (p) => set((s) => ({ settings: { ...s.settings, ...p } })),

      setSidebar: (s) => set({ sidebar: s }),
    }),
    {
      name: "zeno-state",
      partialize: (s) => ({ tabs: s.tabs, settings: s.settings, activeTabId: s.activeTabId }),
    },
  ),
);
