import { invoke } from "@tauri-apps/api/core";

export const GLOBAL_SHORTCUT_KEY = "tobro.globalShortcut";

export function readGlobalShortcut(): string {
  try {
    return localStorage.getItem(GLOBAL_SHORTCUT_KEY) ?? "";
  } catch {
    return "";
  }
}

export async function applyGlobalShortcut(shortcut: string | null | undefined) {
  const value = typeof shortcut === "string" ? shortcut.trim() : "";
  try {
    localStorage.setItem(GLOBAL_SHORTCUT_KEY, value);
  } catch {
    // ignore
  }
  await invoke("set_global_shortcut", { shortcut: value || null });
}

export function initGlobalShortcut() {
  const value = readGlobalShortcut();
  void (async () => {
    try {
      await invoke("set_global_shortcut", { shortcut: value || null });
    } catch {
      // best-effort on startup; user can reconfigure in Settings
    }
  })();
}
