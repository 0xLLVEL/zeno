import type { AttachStatus, ProcessInfo, Settings } from "../types";

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

let invokeImpl: InvokeFn | null = null;

async function getInvoke(): Promise<InvokeFn> {
  if (!isTauri) throw new Error("not running under tauri");
  if (!invokeImpl) {
    const mod = await import("@tauri-apps/api/core");
    invokeImpl = mod.invoke as InvokeFn;
  }
  return invokeImpl;
}

export const api = {
  isTauri,

  async listProcesses(): Promise<ProcessInfo[]> {
    if (!isTauri) return [];
    return (await getInvoke())<ProcessInfo[]>("list_roblox_processes");
  },

  async attach(pid: number, method: Settings["injectionMethod"]): Promise<AttachStatus> {
    if (!isTauri) {
      return {
        attached: true,
        pid,
        process: "RobloxPlayerBeta.exe",
        injected: true,
        message: "preview mode — simulated attach",
      };
    }
    return (await getInvoke())<AttachStatus>("attach", { pid, method });
  },

  async detach(): Promise<void> {
    if (!isTauri) return;
    await (await getInvoke())("detach");
  },

  async status(): Promise<AttachStatus> {
    if (!isTauri) {
      return { attached: false, pid: null, process: null, injected: false, message: "preview mode" };
    }
    return (await getInvoke())<AttachStatus>("attach_status");
  },

  async execute(script: string): Promise<{ ok: boolean; error?: string }> {
    if (!isTauri) {
      await new Promise((r) => setTimeout(r, 120));
      return { ok: true };
    }
    return (await getInvoke())<{ ok: boolean; error?: string }>("execute_script", { script });
  },

  async drainOutput(): Promise<string[]> {
    if (!isTauri) return [];
    return (await getInvoke())<string[]>("drain_output");
  },

  async injectDll(path: string): Promise<void> {
    if (!isTauri) return;
    await (await getInvoke())("inject_custom_dll", { path });
  },
};
