import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";

export const CAPTURE_PROTECTION_KEY = "tobro.captureProtection.enabled";
const CAPTURE_PROTECTION_EVENT = "tobro-capture-protection-changed";

export function readCaptureProtectionEnabled(): boolean {
  try {
    const v = localStorage.getItem(CAPTURE_PROTECTION_KEY);
    if (v === "false") return false;
    if (v === "true") return true;
  } catch {
    // ignore
  }
  return true; // default on (best-effort)
}

async function applyCaptureProtection(enabled: boolean) {
  try {
    await invoke("set_capture_protection", { enabled });
  } catch {
    // best-effort: command may fail on unsupported platforms or restricted contexts
  }
}

export async function setCaptureProtectionEnabled(enabled: boolean) {
  try {
    localStorage.setItem(CAPTURE_PROTECTION_KEY, String(enabled));
  } catch {
    // ignore
  }
  await applyCaptureProtection(enabled);
  window.dispatchEvent(
    new CustomEvent(CAPTURE_PROTECTION_EVENT, { detail: enabled }),
  );
  try {
    await emit(CAPTURE_PROTECTION_EVENT, { enabled });
  } catch {
    // ignore
  }
}

export function initCaptureProtection() {
  const enabled = readCaptureProtectionEnabled();
  void applyCaptureProtection(enabled);

  const sync = () =>
    void applyCaptureProtection(readCaptureProtectionEnabled());

  window.addEventListener("storage", (e) => {
    if (e.key === CAPTURE_PROTECTION_KEY) sync();
  });
  window.addEventListener(CAPTURE_PROTECTION_EVENT, sync);
  window.addEventListener("focus", sync);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") sync();
  });

  void (async () => {
    try {
      await listen<{ enabled?: boolean }>(CAPTURE_PROTECTION_EVENT, (event) => {
        const next = event.payload?.enabled;
        if (typeof next === "boolean") {
          try {
            localStorage.setItem(CAPTURE_PROTECTION_KEY, String(next));
          } catch {
            // ignore
          }
          void applyCaptureProtection(next);
        } else {
          sync();
        }
      });
    } catch {
      // ignore
    }
  })();
}
