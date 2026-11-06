export type LogLevel = "info" | "ok" | "warn" | "error" | "out";

export interface LogEntry {
  id: number;
  level: LogLevel;
  text: string;
  time: number;
}

export interface ScriptTab {
  id: string;
  name: string;
  source: string;
  dirty: boolean;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  path: string;
  version: string;
}

export interface AttachStatus {
  attached: boolean;
  pid: number | null;
  process: string | null;
  injected: boolean;
  message: string;
}

export interface Settings {
  autoAttach: boolean;
  editorFontSize: number;
  editorMinimap: boolean;
  wrapLines: boolean;
  autoExecute: boolean;
  consoleMaxLines: number;
  accent: string;
  injectionMethod: "loadlibrary" | "manualmap" | "section";
}

export interface HubScript {
  id: string;
  name: string;
  author: string;
  description: string;
  tags: string[];
  source: string;
}

export const DEFAULT_SOURCE = `-- Zeno | Luau Executor
-- Ctrl+Enter to execute

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

print("zeno attached to " .. game.Name)
print("local player: " .. LocalPlayer.Name)

-- your script here
`;
