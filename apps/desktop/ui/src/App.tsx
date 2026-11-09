import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useEffect, useMemo, useRef, useState } from "react";
import appIconUrl from "./assets/icon.svg";
import { LogViewer, type LogEntry } from "./LogViewer";

type DaemonState =
  | "starting"
  | "bootstrapping"
  | "connected"
  | "serving"
  | "stopping"
  | "stopped"
  | "error";

interface BootstrapProgress {
  percent?: number;
  ready?: boolean;
  blocked?: string | null;
  detail?: string;
}

interface DaemonStatus {
  state?: DaemonState | string;
  bootstrap?: BootstrapProgress;
  socks_port?: number;
  http_port?: number;
  dns_port?: number;
  bind_all_interfaces?: boolean;
}

interface TobroEvent {
  kind: string;
  payload: unknown;
}

function formatStatus(status: DaemonStatus | null, reachable: boolean): string {
  if (!reachable) return "Daemon unavailable";
  if (!status) return "Waiting for status…";
  const bootstrap = status.bootstrap;
  const percent = typeof bootstrap?.percent === "number" ? `${bootstrap.percent}%` : "";
  const detail = bootstrap?.detail ? ` — ${bootstrap.detail}` : "";
  if (status.state === "bootstrapping") return `Bootstrapping ${percent}${detail}`.trim();
  if (status.state === "connected" || status.state === "serving") {
    return `Connected${percent ? ` (${percent})` : ""}${detail}`;
  }
  if (status.state === "stopping") return "Stopping…";
  if (status.state === "stopped") return "Stopped";
  if (status.state === "error") return `Error${detail}`;
  return String(status.state ?? "Unknown");
}

export default function App() {
  const [status, setStatus] = useState<DaemonStatus | null>(null);
  const [reachable, setReachable] = useState(false);
  const [daemonInfo, setDaemonInfo] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const nextLogId = useRef(1);

  function appendLog(text: string, level: "info" | "error" = "info", source?: string) {
    const entry: LogEntry = {
      id: nextLogId.current++,
      ts: new Date().toISOString(),
      text,
      level,
      source,
    };
    setLogs((prev) => [...prev.slice(-499), entry]);
  }

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    (async () => {
      unlisten = await listen<TobroEvent>("tobro-event", (event) => {
        const { kind, payload } = event.payload;
        if (kind === "status") {
          if (payload && typeof payload === "object") {
            setStatus(payload as DaemonStatus);
            setReachable(true);
          } else {
            setStatus(null);
          }
          return;
        }
        if (kind === "reachable") {
          setReachable(true);
          const p = payload as { socket?: string };
          if (p?.socket) setDaemonInfo(`socket: ${p.socket}`);
          return;
        }
        if (kind === "hello") {
          const h = payload as {
            daemon_version?: string;
            rpc_version?: number;
            platform?: string;
            arti_version?: string;
          };
          setDaemonInfo(
            `daemon ${h.daemon_version ?? "?"} (rpc v${h.rpc_version ?? "?"}, ${h.platform ?? "?"}, arti ${h.arti_version ?? "?"})`,
          );
          return;
        }
        if (kind === "unreachable") {
          setReachable(false);
          const p = payload as { error?: string };
          if (p?.error) appendLog(p.error, "error", "daemon");
          return;
        }
        if (kind === "event") {
          const e = payload as { method?: string; params?: unknown };
          if (e.method === "bootstrap.progress") {
            const b = (e.params ?? {}) as BootstrapProgress;
            appendLog(
              `bootstrap ${typeof b.percent === "number" ? `${b.percent}%` : ""}${b.detail ? ` — ${b.detail}` : ""}`.trim(),
              "info",
              "daemon",
            );
          } else if (e.method === "daemon.state_changed") {
            const s = (e.params ?? {}) as { state?: string; message?: string };
            const detail = s.message ? ` — ${s.message}` : "";
            appendLog(`state → ${s.state ?? "?"}${detail}`, s.state === "error" ? "error" : "info", "daemon");
          } else if (e.method) {
            appendLog(`${e.method}`, "info", "daemon");
          }
        }
      });
      try {
        const initial = await invoke<DaemonStatus>("status");
        if (initial) setStatus(initial);
      } catch {
        // daemon watcher will report reachability
      }
    })();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const headline = useMemo(() => formatStatus(status, reachable), [status, reachable]);
  const isActive = status?.state === "starting" || status?.state === "bootstrapping" || status?.state === "connected" || status?.state === "serving";
  // Allow Connect even when the local daemon is unavailable so the desktop can
  // start tobrod and connect with a single button (Orbot parity).
  const canConnect = !busy && !isActive && status?.state !== "stopping";
  const canNewIdentity = reachable && !busy && (status?.state === "connected" || status?.state === "serving");

  async function openSettings() {
    try {
      const existing = await WebviewWindow.getByLabel("settings");
      if (existing) {
        await existing.show();
        await existing.setFocus();
        return;
      }
      const settings = new WebviewWindow("settings", {
        url: "index.html?window=settings",
        title: "Settings — Tobro",
        width: 820,
        height: 720,
        minWidth: 560,
        minHeight: 480,
        resizable: true,
        center: true,
      });
      settings.once("tauri://error", (e) => {
        appendLog(`settings window error: ${JSON.stringify(e.payload ?? e)}`, "error", "ui");
      });
    } catch (e) {
      appendLog(`failed to open settings: ${String(e)}`, "error", "ui");
    }
  }

  async function openAbout() {
    try {
      const existing = await WebviewWindow.getByLabel("about");
      if (existing) {
        await existing.show();
        await existing.setFocus();
        return;
      }
      const about = new WebviewWindow("about", {
        url: "index.html?window=about",
        title: "About — Tobro",
        width: 760,
        height: 680,
        minWidth: 520,
        minHeight: 420,
        resizable: true,
        center: true,
      });
      about.once("tauri://error", (e) => {
        appendLog(`about window error: ${JSON.stringify(e.payload ?? e)}`, "error", "ui");
      });
    } catch (e) {
      appendLog(`failed to open about: ${String(e)}`, "error", "ui");
    }
  }

  async function onConnect() {
    setBusy(true);
    appendLog("requesting connect…", "info", "ui");
    try {
      const result = await invoke<{ status?: string }>("daemon_connect");
      if (result?.status) appendLog(String(result.status), "info", "ui");
    } catch (e) {
      appendLog(String(e), "error", "ui");
    } finally {
      setBusy(false);
    }
  }

  async function onStop() {
    setBusy(true);
    appendLog("requesting stop…", "info", "ui");
    try {
      await invoke("daemon_stop");
    } catch (e) {
      appendLog(String(e), "error", "ui");
    } finally {
      setBusy(false);
    }
  }

  async function onNewIdentity() {
    setBusy(true);
    appendLog("requesting new identity (new circuits)…", "info", "ui");
    try {
      const result = await invoke<{ note?: string }>("daemon_new_identity");
      if (result?.note) appendLog(result.note, "info", "daemon");
    } catch (e) {
      appendLog(String(e), "error", "ui");
    } finally {
      setBusy(false);
    }
  }

  const percent = Math.max(0, Math.min(100, status?.bootstrap?.percent ?? 0));
  const showProgress = isActive || status?.state === "error";

  return (
    <main className="app">
      <header className="hero">
        <div className="brand">
          <img src={appIconUrl} alt="" className="app-icon" width={44} height={44} />
          <div>
            <h1>Tobro</h1>
            <p className="muted">{daemonInfo || "Connecting to local daemon…"}</p>
          </div>
        </div>
        <nav className="toolbar" aria-label="App actions">
          <button type="button" onClick={onNewIdentity} disabled={!canNewIdentity} title="Request new circuits (implemented). Guard state preserved.">
            New identity
          </button>
          <button type="button" disabled title="Change exit country (coming soon)">
            Change exit
          </button>
          <button type="button" onClick={() => void openSettings()} aria-haspopup="dialog" title="Settings">
            Settings
          </button>
          <button type="button" onClick={() => void openAbout()} aria-haspopup="dialog" title="About">
            About
          </button>
        </nav>
      </header>

      <section className={`card status status-${status?.state ?? "unknown"} ${reachable ? "" : "unreachable"}`}>
        <p className="headline">{headline}</p>
        {showProgress ? (
          <div className="progress" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
            <div className="progress-bar" style={{ width: `${percent}%` }} />
          </div>
        ) : null}
        {status?.bootstrap?.blocked ? <p className="blocked">Blocked: {status.bootstrap.blocked}</p> : null}
        {status?.bind_all_interfaces ? (
          <p className="error bind-all-warning" role="alert">
            Security warning: listeners are bound to all interfaces (SOCKS/HTTP/DNS exposed beyond localhost). Use firewall rules and trusted networks only.
          </p>
        ) : null}
        <div className="ports muted">
          <span>active SOCKS {status?.bind_all_interfaces ? "0.0.0.0:" : "127.0.0.1:"}{status?.socks_port ?? "—"}</span>
          <span>active HTTP {status?.bind_all_interfaces ? "0.0.0.0:" : "127.0.0.1:"}{status?.http_port ?? status?.socks_port ?? "—"}</span>
          <span>active DNS {status?.bind_all_interfaces ? "0.0.0.0:" : "127.0.0.1:"}{status?.dns_port ?? "—"}</span>
        </div>
        <p className="muted ports-hint">
          Proxy, node, and advanced Tor settings are in <button type="button" className="link-button" onClick={() => void openSettings()}>Settings</button>.
        </p>
        <div className="actions">
          {!isActive ? (
            <button className="primary" onClick={onConnect} disabled={!canConnect}>
              Connect
            </button>
          ) : (
            <>
              <button
                type="button"
                onClick={onNewIdentity}
                disabled={!canNewIdentity}
                title="Request new circuits. Guard state is preserved; this is not identical to Tor's NEWNYM."
              >
                New identity
              </button>
              <button className="danger" onClick={onStop} disabled={!reachable || busy || status?.state === "stopping"}>
                Stop
              </button>
            </>
          )}
        </div>
      </section>

      <LogViewer entries={logs} onClear={() => setLogs([])} defaultOpen={false} />
    </main>
  );
}
