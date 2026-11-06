import { useEffect } from "react";
import { Sidebar } from "./components/Sidebar";
import { TitleBar } from "./components/TitleBar";
import { EditorPane, useExecuteHook } from "./components/EditorPane";
import { ConsolePane } from "./components/ConsolePane";
import { ScriptHub } from "./components/ScriptHub";
import { SettingsPanel } from "./components/SettingsPanel";
import { StatusBar, useKeyboardShortcuts } from "./components/StatusBar";
import { useOutputPump, useStatusPoller } from "./hooks/useZeno";
import { useZeno } from "./store";

export default function App() {
  const sidebar = useZeno((s) => s.sidebar);
  const execute = useExecuteHook();

  useOutputPump();
  useStatusPoller();
  useKeyboardShortcuts(execute);

  useEffect(() => {
    const handler = (e: ErrorEvent) => {
      useZeno.getState().log("error", e.message);
    };
    window.addEventListener("error", handler);
    return () => window.removeEventListener("error", handler);
  }, []);

  return (
    <div className="app">
      <TitleBar onExecute={execute} />
      <div className="body">
        <Sidebar />
        <main className="main">
          {sidebar === "editor" && <EditorPane />}
          {sidebar === "console" && <ConsolePane />}
          {sidebar === "hub" && <ScriptHub />}
          {sidebar === "settings" && <SettingsPanel />}
        </main>
      </div>
      <StatusBar />
    </div>
  );
}
