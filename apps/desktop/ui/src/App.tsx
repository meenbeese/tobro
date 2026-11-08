import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useMemo, useRef, useState } from "react";
import appIconUrl from "./assets/icon.svg";
import { ConfigPanel } from "./ConfigPanel";
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
}

interface ProxyPorts {
  socks_port: number;
  http_port: number;
  dns_port: number;
  config_path?: string;
}

interface TobroEvent {
  kind: string;
  payload: unknown;
}

function parsePort(value: string): number | null {
  if (!/^\d+$/.test(value)) return null;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return port;
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

type PortField = "socks_port" | "http_port" | "dns_port";

export default function App() {
  const [status, setStatus] = useState<DaemonStatus | null>(null);
  const [reachable, setReachable] = useState(false);
  const [daemonInfo, setDaemonInfo] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [portInputs, setPortInputs] = useState<Record<PortField, string>>({
    socks_port: "9050",
    http_port: "9050",
    dns_port: "9053",
  });
  const [configPath, setConfigPath] = useState<string>("");
  const [portsDirty, setPortsDirty] = useState(false);
  const [portsBusy, setPortsBusy] = useState(false);
  const [portsMessage, setPortsMessage] = useState<string>("");
  const [portsError, setPortsError] = useState<string>("");
  const [settingsOpen, setSettingsOpen] = useState(false);
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

  async function loadPorts() {
    try {
      const loaded = await invoke<ProxyPorts>("get_proxy_ports");
      setPortInputs({
        socks_port: String(loaded.socks_port),
        http_port: String(loaded.http_port),
        dns_port: String(loaded.dns_port),
      });
      setConfigPath(loaded.config_path ?? "");
      setPortsDirty(false);
      setPortsError("");
    } catch (e) {
      setPortsError(String(e));
    }
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
      await loadPorts();
    })();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const headline = useMemo(() => formatStatus(status, reachable), [status, reachable]);
  const isActive = status?.state === "bootstrapping" || status?.state === "connected" || status?.state === "serving";
  const canAct = reachable && !busy && status?.state !== "starting" && status?.state !== "stopping";
  const canNewIdentity = canAct && (status?.state === "connected" || status?.state === "serving");

  function onPlaceholder(feature: string) {
    appendLog(`${feature}: coming soon.`, "info", "ui");
  }

  async function onConnect() {
    setBusy(true);
    appendLog("requesting connect…", "info", "ui");
    try {
      await invoke("daemon_connect");
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

  function updatePort(field: PortField, value: string) {
    setPortsDirty(true);
    setPortsError("");
    setPortsMessage("");
    setPortInputs((prev) => {
      const next = { ...prev, [field]: value };
      if (field === "socks_port") {
        const socksWasFollowing = prev.http_port === prev.socks_port || prev.http_port === "0";
        if (socksWasFollowing) next.http_port = value;
      }
      return next;
    });
  }

  async function onSavePorts() {
    const socksPort = parsePort(portInputs.socks_port);
    const httpPortRaw = parsePort(portInputs.http_port);
    const dnsPort = parsePort(portInputs.dns_port);
    if (socksPort === null || dnsPort === null || portInputs.http_port.trim() === "" || httpPortRaw === null) {
      const message =
        httpPortRaw === null && portInputs.http_port.trim() === "0"
          ? null
          : "Ports must be integers: SOCKS/DNS 1–65535, HTTP 0–65535 (0 follows SOCKS).";
      if (message) {
        setPortsError(message);
        return;
      }
    }
    const httpPort = portInputs.http_port.trim() === "0" ? 0 : httpPortRaw;
    if (socksPort === null || httpPort === null || dnsPort === null) {
      setPortsError("Ports must be integers: SOCKS/DNS 1–65535, HTTP 0–65535 (0 follows SOCKS).");
      return;
    }

    setPortsBusy(true);
    setPortsError("");
    setPortsMessage("");
    try {
      const result = await invoke<{
        ok?: boolean;
        proxy?: ProxyPorts;
        reload?: { apply?: string; warnings?: string[] } | null;
      }>("save_proxy_ports", {
        socksPort,
        httpPort,
        dnsPort,
      });
      if (result.proxy) {
        setPortInputs({
          socks_port: String(result.proxy.socks_port),
          http_port: String(result.proxy.http_port),
          dns_port: String(result.proxy.dns_port),
        });
        setConfigPath(result.proxy.config_path ?? configPath);
      }
      setPortsDirty(false);
      const apply = result.reload?.apply;
      const warnings = result.reload?.warnings ?? [];
      const msg = apply ? `Saved. ${apply}` : "Saved to config.";
      setPortsMessage(warnings.length ? `${msg} Warnings: ${warnings.join(" | ")}` : msg);
      appendLog(`ports saved (SOCKS ${socksPort}, HTTP ${httpPort || socksPort}, DNS ${dnsPort})`, "info", "ui");
      if (warnings.length) appendLog(warnings.join(" | "), "error", "ui");
    } catch (e) {
      const message = String(e);
      setPortsError(message);
      appendLog(message, "error", "ui");
    } finally {
      setPortsBusy(false);
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
          <button type="button" onClick={() => setSettingsOpen((v) => !v)} aria-expanded={settingsOpen} title="Config import/export and settings">
            Settings
          </button>
          <button type="button" onClick={() => onPlaceholder("About")} title="About (coming soon)">
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
        <div className="ports muted">
          <span>active SOCKS {status?.socks_port ?? "—"}</span>
          <span>active HTTP {status?.http_port ?? status?.socks_port ?? "—"}</span>
          <span>active DNS {status?.dns_port ?? "—"}</span>
        </div>
        <form
          className="port-editor"
          onSubmit={(e) => {
            e.preventDefault();
            void onSavePorts();
          }}
        >
          <h2>Listener ports</h2>
          <p className="muted">
            Configure local SOCKS/HTTP and DNS ports. With the current Arti backend, SOCKS and HTTP share one listener, so HTTP should match SOCKS (use <code>0</code> to follow SOCKS). Changes apply on the next connection; active listeners require stop/connect.
          </p>
          <div className="port-grid">
            <label>
              SOCKS
              <input
                type="number"
                min={1}
                max={65535}
                inputMode="numeric"
                value={portInputs.socks_port}
                onChange={(e) => updatePort("socks_port", e.target.value)}
              />
            </label>
            <label>
              HTTP
              <input
                type="number"
                min={0}
                max={65535}
                inputMode="numeric"
                value={portInputs.http_port}
                onChange={(e) => updatePort("http_port", e.target.value)}
              />
            </label>
            <label>
              DNS
              <input
                type="number"
                min={1}
                max={65535}
                inputMode="numeric"
                value={portInputs.dns_port}
                onChange={(e) => updatePort("dns_port", e.target.value)}
              />
            </label>
          </div>
          {configPath ? <p className="muted config-hint">Config: <code>{configPath}</code></p> : null}
          {portsError ? <p className="error">{portsError}</p> : null}
          {portsMessage ? <p className="muted">{portsMessage}</p> : null}
          <div className="actions">
            <button className="primary" type="submit" disabled={portsBusy || !portsDirty}>
              {portsBusy ? "Saving…" : "Save ports"}
            </button>
            <button type="button" onClick={() => void loadPorts()} disabled={portsBusy}>
              Reset
            </button>
          </div>
        </form>
        <div className="actions">
          {!isActive ? (
            <button className="primary" onClick={onConnect} disabled={!canAct}>
              Connect
            </button>
          ) : (
            <>
              <button
                type="button"
                onClick={onNewIdentity}
                disabled={!canAct || status?.state !== "connected" && status?.state !== "serving"}
                title="Request new circuits. Guard state is preserved; this is not identical to Tor's NEWNYM."
              >
                New identity
              </button>
              <button className="danger" onClick={onStop} disabled={!canAct}>
                Stop
              </button>
            </>
          )}
        </div>
      </section>

      {settingsOpen ? (
        <ConfigPanel
          onClose={() => setSettingsOpen(false)}
          onApplied={() => void loadPorts()}
          appendLog={appendLog}
        />
      ) : null}

      <LogViewer entries={logs} onClear={() => setLogs([])} defaultOpen={false} />
    </main>
  );
}
