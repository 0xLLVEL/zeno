import { useState } from "react";
import { useZeno } from "../store";
import { api } from "../lib/api";

const ACCENTS = ["#7c5cff", "#4fd1c5", "#ff6b9d", "#f6ad55", "#63b3ed", "#9ae6b4"];

export function SettingsPanel() {
  const { settings, patchSettings, log } = useZeno();
  const [dllPath, setDllPath] = useState("");

  const pickDll = async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const p = await open({ multiple: false, filters: [{ name: "DLL", extensions: ["dll"] }] });
      if (typeof p === "string") setDllPath(p);
    } catch (e) {
      log("error", String(e));
    }
  };

  return (
    <div className="pane settings-pane">
      <h2>Settings</h2>

      <section>
        <h3>Attach</h3>
        <label className="row">
          <span>auto-attach on launch</span>
          <input
            type="checkbox"
            checked={settings.autoAttach}
            onChange={(e) => patchSettings({ autoAttach: e.target.checked })}
          />
        </label>
        <label className="row">
          <span>injection method</span>
          <select
            value={settings.injectionMethod}
            onChange={(e) =>
              patchSettings({
                injectionMethod: e.target.value as "loadlibrary" | "manualmap" | "section",
              })
            }
          >
            <option value="loadlibrary">LoadLibrary (standard)</option>
            <option value="manualmap">Manual Map (stealth)</option>
            <option value="section">Section Image (file-backed)</option>
          </select>
        </label>

        <div className="row">
          <span>inject custom dll</span>
          <div className="inline">
            <input
              className="path-input"
              placeholder="C:\\path\\to\\module.dll"
              value={dllPath}
              onChange={(e) => setDllPath(e.target.value)}
            />
            <button className="mini" onClick={pickDll}>
              browse
            </button>
            <button
              className="mini accent"
              disabled={!dllPath}
              onClick={async () => {
                try {
                  await api.injectDll(dllPath);
                  log("ok", `injected ${dllPath.split(/[\\/]/).pop()}`);
                } catch (e) {
                  log("error", String(e));
                }
              }}
            >
              inject
            </button>
          </div>
        </div>
      </section>

      <section>
        <h3>Editor</h3>
        <label className="row">
          <span>font size</span>
          <input
            type="range"
            min={11}
            max={24}
            value={settings.editorFontSize}
            onChange={(e) => patchSettings({ editorFontSize: Number(e.target.value) })}
          />
          <span className="val">{settings.editorFontSize}px</span>
        </label>
        <label className="row">
          <span>minimap</span>
          <input
            type="checkbox"
            checked={settings.editorMinimap}
            onChange={(e) => patchSettings({ editorMinimap: e.target.checked })}
          />
        </label>
        <label className="row">
          <span>word wrap</span>
          <input
            type="checkbox"
            checked={settings.wrapLines}
            onChange={(e) => patchSettings({ wrapLines: e.target.checked })}
          />
        </label>
      </section>

      <section>
        <h3>Console</h3>
        <label className="row">
          <span>max lines</span>
          <input
            type="number"
            min={200}
            max={20000}
            step={100}
            value={settings.consoleMaxLines}
            onChange={(e) => patchSettings({ consoleMaxLines: Number(e.target.value) })}
          />
        </label>
      </section>

      <section>
        <h3>Appearance</h3>
        <div className="row">
          <span>accent</span>
          <div className="swatches">
            {ACCENTS.map((c) => (
              <button
                key={c}
                className={`swatch ${settings.accent === c ? "on" : ""}`}
                style={{ background: c }}
                onClick={() => patchSettings({ accent: c })}
                aria-label={c}
              />
            ))}
          </div>
        </div>
      </section>

      <section>
        <h3>About</h3>
        <div className="about">
          <div className="about-logo">Z</div>
          <div>
            <strong>Zeno</strong>
            <div className="dim">v1.0.0 · tauri 2 · react 18</div>
            <div className="dim">executor core: luau 0.6xx · named-pipe bridge</div>
          </div>
        </div>
      </section>
    </div>
  );
}
