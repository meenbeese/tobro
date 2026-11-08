import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useMemo, useRef, useState } from "react";

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
}

interface LogEntry {
  id: number;
  text: string;
  level: "info" | "error";
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

  function appendLog(text: string, level: "info" | "error" = "info") {
    const entry = { id: nextLogId.current++, text, level };
    setLogs((prev) => [...prev.slice(-199), entry]);
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
          if (p?.error) appendLog(p.error, "error");
          return;
        }
        if (kind === "event") {
          const e = payload as { method?: string; params?: unknown };
          if (e.method === "bootstrap.progress") {
            const b = (e.params ?? {}) as BootstrapProgress;
            appendLog(
              `bootstrap ${typeof b.percent === "number" ? `${b.percent}%` : ""}${b.detail ? ` — ${b.detail}` : ""}`.trim(),
            );
          } else if (e.method === "daemon.state_changed") {
            const s = (e.params ?? {}) as { state?: string };
            appendLog(`state → ${s.state ?? "?"}`);
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
  const isActive = status?.state === "bootstrapping" || status?.state === "connected" || status?.state === "serving";
  const canAct = reachable && !busy && status?.state !== "starting" && status?.state !== "stopping";

  async function onConnect() {
    setBusy(true);
    appendLog("requesting connect…");
    try {
      await invoke("daemon_connect");
    } catch (e) {
      appendLog(String(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function onStop() {
    setBusy(true);
    appendLog("requesting stop…");
    try {
      await invoke("daemon_stop");
    } catch (e) {
      appendLog(String(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const percent = Math.max(0, Math.min(100, status?.bootstrap?.percent ?? 0));
  const showProgress = isActive || status?.state === "error";

  return (
    <main className="app">
      <header className="hero">
        <div>
          <h1>tobro</h1>
          <p className="muted">{daemonInfo || "Connecting to local daemon…"}</p>
        </div>
      </header>

      <section className={`card status status-${status?.state ?? "unknown"} ${reachable ? "" : "unreachable"}`}>
        <p className="headline">{headline}</p>
        {showProgress ? (
          <div className="progress" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
            <div className="progress-bar" style={{ width: `${percent}%` }} />
          </div>
        ) : null}
        {status?.bootstrap?.blocked ? <p className="blocked">Blocked: {status.bootstrap.blocked}</p> : null}
        <div className="ports muted">
          <span>SOCKS {status?.socks_port ?? "—"}</span>
          <span>HTTP {status?.http_port ?? status?.socks_port ?? "—"}</span>
          <span>DNS {status?.dns_port ?? "—"}</span>
        </div>
        <p className="muted config-hint">
          Listener ports are configured in <code>config.toml</code> (<code>proxy.socks_port</code>, <code>proxy.http_port</code>, <code>proxy.dns_port</code>). Edit the file, then run <code>tobroctl reload-config</code> or restart the connection.
        </p>
        <div className="actions">
          {!isActive ? (
            <button className="primary" onClick={onConnect} disabled={!canAct}>
              Connect
            </button>
          ) : (
            <button className="danger" onClick={onStop} disabled={!canAct}>
              Stop
            </button>
          )}
        </div>
      </section>

      <section className="card logs">
        <h2>Log</h2>
        <ol aria-label="Event log">
          {logs.length === 0 ? <li className="muted">No events yet.</li> : null}
          {logs.map((entry) => (
            <li key={entry.id} className={entry.level === "error" ? "error" : ""}>
              {entry.text}
            </li>
          ))}
        </ol>
      </section>
    </main>
  );
}
