export type ThemePreference = "system" | "light" | "dark";

export const THEME_KEY = "tobro.theme";
const THEME_EVENT = "tobro-theme-changed";

export function readThemePreference(): ThemePreference {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    // ignore
  }
  return "system";
}

export function systemPrefersDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches;
}

export function resolvedTheme(pref: ThemePreference): "light" | "dark" {
  if (pref === "light" || pref === "dark") return pref;
  return systemPrefersDark() ? "dark" : "light";
}

export function applyThemePreference(pref: ThemePreference) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (pref === "system") {
    root.removeAttribute("data-theme");
    root.style.colorScheme = "light dark";
  } else {
    root.dataset.theme = pref;
    root.style.colorScheme = pref;
  }
}

export function setThemePreference(pref: ThemePreference) {
  try {
    localStorage.setItem(THEME_KEY, pref);
  } catch {
    // ignore
  }
  applyThemePreference(pref);
  window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: pref }));
  void broadcastThemeChange(pref);
}

async function broadcastThemeChange(pref: ThemePreference) {
  try {
    const { emit } = await import("@tauri-apps/api/event");
    await emit(THEME_EVENT, { theme: pref });
  } catch {
    // not in Tauri or emit unavailable
  }
}

export function initTheme() {
  applyThemePreference(readThemePreference());

  const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
  const onSystemChange = () => {
    if (readThemePreference() === "system") applyThemePreference("system");
  };
  mq?.addEventListener?.("change", onSystemChange);

  const sync = () => applyThemePreference(readThemePreference());

  // Same-origin storage propagation (when supported by the webview)
  window.addEventListener("storage", (e) => {
    if (e.key === THEME_KEY) sync();
  });
  // Same-window propagation
  window.addEventListener(THEME_EVENT, sync);
  // Reliable fallback: re-apply when the window regains focus/visibility
  // (covers Settings->main switches where storage events may not fire)
  window.addEventListener("focus", sync);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") sync();
  });

  // Tauri cross-webview propagation
  void (async () => {
    try {
      const { listen } = await import("@tauri-apps/api/event");
      await listen<{ theme?: ThemePreference }>(THEME_EVENT, (event) => {
        const t = event.payload?.theme;
        if (t === "light" || t === "dark" || t === "system") {
          try {
            localStorage.setItem(THEME_KEY, t);
          } catch {
            // ignore
          }
          applyThemePreference(t);
        } else {
          sync();
        }
      });
    } catch {
      // not in Tauri or listen unavailable
    }
  })();
}
