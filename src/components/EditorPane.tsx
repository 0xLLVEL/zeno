import { useCallback, useEffect, useRef } from "react";
import Editor, { OnMount } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import { useZeno } from "../store";
import { luauLanguage, zinTheme } from "../lib/monaco-luau";
import { api } from "../lib/api";
import { TabsBar } from "./TabsBar";

export function EditorPane() {
  const { tabs, activeTabId, updateSource, settings, addTab } = useZeno();
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const active = tabs.find((t) => t.id === activeTabId) ?? tabs[0];

  useEffect(() => {
    document.body.style.setProperty("--accent", settings.accent);
  }, [settings.accent]);

  const onMount: OnMount = (ed, monaco) => {
    editorRef.current = ed;

    if (!monaco.languages.getLanguages().some((l) => l.id === "luau")) {
      monaco.languages.register({ id: "luau", extensions: [".lua", ".luau"] });
      monaco.languages.setMonarchTokensProvider("luau", luauLanguage as never);
      monaco.languages.setLanguageConfiguration("luau", {
        comments: { lineComment: "--", blockComment: ["--[[", "]]"] },
        brackets: [
          ["{", "}"],
          ["[", "]"],
          ["(", ")"],
        ],
        autoClosingPairs: [
          { open: "{", close: "}" },
          { open: "[", close: "]" },
          { open: "(", close: ")" },
          { open: '"', close: '"' },
          { open: "'", close: "'" },
        ],
        surroundingPairs: [
          { open: "{", close: "}" },
          { open: "[", close: "]" },
          { open: "(", close: ")" },
          { open: '"', close: '"' },
          { open: "'", close: "'" },
        ],
      });
    }

    monaco.editor.defineTheme("zeno", zinTheme as never);
    monaco.editor.setTheme("zeno");

    ed.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
      document.dispatchEvent(new CustomEvent("zeno:execute"));
    });

    ed.focus();
  };

  const openFile = useCallback(async () => {
    try {
      const [{ open }, { readTextFile }] = await Promise.all([
        import("@tauri-apps/plugin-dialog"),
        import("@tauri-apps/plugin-fs"),
      ]);
      const path = await open({
        multiple: false,
        filters: [{ name: "Luau", extensions: ["lua", "luau", "txt"] }],
      });
      if (typeof path !== "string") return;
      const text = await readTextFile(path);
      const name = path.split(/[\\/]/).pop() ?? "script.lua";
      addTab(name, text);
    } catch (e) {
      useZeno.getState().log("error", `open failed: ${String(e)}`);
    }
  }, [addTab]);

  return (
    <div className="pane editor-pane">
      <TabsBar onOpenFile={openFile} />

      <div className="editor-host">
        {active && (
          <Editor
            key={active.id}
            height="100%"
            language="luau"
            theme="zeno"
            value={active.source}
            onChange={(v) => updateSource(active.id, v ?? "")}
            onMount={onMount}
            options={{
              fontSize: settings.editorFontSize,
              fontFamily: "'JetBrains Mono', 'Cascadia Code', Consolas, monospace",
              fontLigatures: true,
              minimap: { enabled: settings.editorMinimap, scale: 0.8 },
              wordWrap: settings.wrapLines ? "on" : "off",
              smoothScrolling: true,
              cursorBlinking: "phase",
              cursorSmoothCaretAnimation: "on",
              renderLineHighlight: "all",
              padding: { top: 14, bottom: 14 },
              scrollBeyondLastLine: false,
              tabSize: 4,
              automaticLayout: true,
              bracketPairColorization: { enabled: true },
              guides: { indentation: true, bracketPairs: true },
              suggest: { showWords: true },
              lineNumbersMinChars: 4,
              scrollbar: { verticalScrollbarSize: 10, horizontalScrollbarSize: 10 },
            }}
          />
        )}
      </div>

      <div className="editor-foot">
        <span className="dim">{active?.name ?? "no file"}</span>
        <span className="dim">luau · {active?.source.split("\n").length ?? 0} lines</span>
      </div>
    </div>
  );
}

export function useExecuteHook() {
  const { tabs, activeTabId, setRunning, log, attached } = useZeno();

  return useCallback(async () => {
    const tab = tabs.find((t) => t.id === activeTabId);
    if (!tab) return;
    if (!attached) {
      log("error", "not attached — attach to roblox first");
      return;
    }
    setRunning(true);
    const t0 = performance.now();
    log("info", `executing ${tab.name} (${tab.source.length} bytes)`);
    try {
      const res = await api.execute(tab.source);
      const ms = (performance.now() - t0).toFixed(1);
      if (res.ok) log("ok", `executed in ${ms}ms`);
      else log("error", res.error ?? "execution failed");
    } catch (e) {
      log("error", String(e));
    } finally {
      setRunning(false);
    }
  }, [tabs, activeTabId, setRunning, log, attached]);
}
