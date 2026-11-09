import { invoke } from "@tauri-apps/api/core";
import { emit, listen, type UnlistenFn } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import appIconUrl from "./assets/icon.svg";
import { StatusIcon } from "./StatusIcon";
import { ConnectionInfo } from "./ConnectionInfo";

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

interface AppLockStatus {
  enabled: boolean;
  lock_on_idle: boolean;
  idle_minutes: number;
  lock_on_close: boolean;
  prefer_os_auth: boolean;
  has_password: boolean;
  os_auth_available: boolean;
  os_auth_method: string;
}

function formatStatus(status: DaemonStatus | null, reachable: boolean): string {
  if (!reachable) return "Ready to connect";
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
  const [lockStatus, setLockStatus] = useState<AppLockStatus | null>(null);
  const [locked, setLocked] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [unlockBusy, setUnlockBusy] = useState(false);
  const [connectedAt, setConnectedAt] = useState<number | null>(null);
  const idleTimer = useRef<number | null>(null);

  function appendLog(text: string, level: "info" | "error" = "info", source = "ui") {
    void emit("tobro-event", {
      kind: "ui.log",
      payload: { text, level, source, ts: new Date().toISOString() },
    });
  }

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    (async () => {
      unlisten = await listen<TobroEvent>("tobro-event", (event) => {
        const { kind, payload } = event.payload;
        if (kind === "status") {
          if (payload && typeof payload === "object") {
            const newStatus = payload as DaemonStatus;
            setStatus((prev) => {
              const prevState = prev?.state;
              const nextState = newStatus.state;
              const wasConnected = prevState === "connected" || prevState === "serving";
              const isNowConnected = nextState === "connected" || nextState === "serving";
              if (!wasConnected && isNowConnected) {
                setConnectedAt(Date.now());
              } else if (wasConnected && !isNowConnected) {
                setConnectedAt(null);
              }
              return newStatus;
            });
            setReachable(true);
          } else {
            setStatus(null);
            setConnectedAt(null);
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
          setStatus(null);
          setConnectedAt(null);
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
        if (initial) {
          setStatus(initial);
          const s = initial.state;
          if (s === "connected" || s === "serving") {
            setConnectedAt((prev) => prev ?? Date.now());
          }
        }
      } catch {
        // daemon watcher will report reachability
      }
    })();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const headline = useMemo(() => formatStatus(status, reachable), [status, reachable]);
  const isActive = reachable && (status?.state === "starting" || status?.state === "bootstrapping" || status?.state === "connected" || status?.state === "serving");
  // Allow Connect even when the local daemon is unavailable so the desktop can
  // start tobrod and connect with a single button (Orbot parity).
  const canConnect = !busy && !isActive && status?.state !== "stopping";
  const canNewIdentity = reachable && !busy && (status?.state === "connected" || status?.state === "serving");

  const refreshLockStatus = useCallback(async (opts?: { lockIfEnabled?: boolean }) => {
    try {
      const s = await invoke<AppLockStatus>("get_app_lock_status");
      setLockStatus(s);
      const shouldBeLockable = s.enabled && s.has_password;
      if (!shouldBeLockable) {
        setLocked(false);
      } else if (opts?.lockIfEnabled) {
        setLocked(true);
      }
      return s;
    } catch (e) {
      appendLog(`app lock status: ${String(e)}`, "error", "ui");
      return null;
    }
  }, []);

  useEffect(() => {
    void refreshLockStatus({ lockIfEnabled: true });
  }, [refreshLockStatus]);

  useEffect(() => {
    if (!lockStatus?.enabled || !lockStatus.lock_on_idle || locked) return;
    const ms = Math.max(1, lockStatus.idle_minutes || 5) * 60_000;
    const reset = () => {
      if (idleTimer.current != null) window.clearTimeout(idleTimer.current);
      idleTimer.current = window.setTimeout(() => {
        setLocked(true);
        setUnlockPassword("");
        setUnlockError("");
      }, ms);
    };
    const events: (keyof WindowEventMap)[] = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"];
    events.forEach((ev) => window.addEventListener(ev, reset, { passive: true }));
    reset();
    return () => {
      events.forEach((ev) => window.removeEventListener(ev, reset));
      if (idleTimer.current != null) {
        window.clearTimeout(idleTimer.current);
        idleTimer.current = null;
      }
    };
  }, [lockStatus?.enabled, lockStatus?.lock_on_idle, lockStatus?.idle_minutes, locked]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden) {
        if (lockStatus?.enabled && lockStatus.lock_on_close) {
          setLocked(true);
          setUnlockPassword("");
          setUnlockError("");
        }
      } else {
        void refreshLockStatus();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [lockStatus?.enabled, lockStatus?.lock_on_close, refreshLockStatus]);

  async function onUnlock(e?: FormEvent) {
    e?.preventDefault();
    setUnlockBusy(true);
    setUnlockError("");
    try {
      const res = await invoke<{ ok?: boolean; locked?: boolean; error?: string }>("unlock_app_lock", {
        password: unlockPassword || null,
        useOsAuth: false,
      });
      if (res?.ok) {
        setLocked(false);
        setUnlockPassword("");
      } else {
        setUnlockError(res?.error || "Unlock failed.");
      }
    } catch (err) {
      setUnlockError(String(err));
    } finally {
      setUnlockBusy(false);
    }
  }

  async function onTryOsAuth() {
    setUnlockBusy(true);
    setUnlockError("");
    try {
      const res = await invoke<{ ok?: boolean; locked?: boolean; error?: string }>("unlock_app_lock", {
        password: null,
        useOsAuth: true,
      });
      if (res?.ok) {
        setLocked(false);
        setUnlockPassword("");
      } else {
        setUnlockError(res?.error || "OS authentication failed. Enter your password.");
      }
    } catch (err) {
      setUnlockError(String(err));
    } finally {
      setUnlockBusy(false);
    }
  }

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

  async function openLogs() {
    try {
      const existing = await WebviewWindow.getByLabel("logs");
      if (existing) {
        await existing.show();
        await existing.setFocus();
        return;
      }
      const logsWindow = new WebviewWindow("logs", {
        url: "index.html?window=logs",
        title: "Logs — Tobro",
        width: 980,
        height: 640,
        minWidth: 640,
        minHeight: 360,
        resizable: true,
        center: true,
      });
      logsWindow.once("tauri://error", (e) => {
        appendLog(`logs window error: ${JSON.stringify(e.payload ?? e)}`, "error", "ui");
      });
    } catch (e) {
      appendLog(`failed to open logs: ${String(e)}`, "error", "ui");
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
    <>
      {locked ? (
        <div className="lock-overlay" role="dialog" aria-modal="true" aria-labelledby="lock-title">
          <form className="lock-card card" onSubmit={(e) => void onUnlock(e)}>
            <h2 id="lock-title">Tobro is locked</h2>
            <p className="muted">
              App lock is enabled. Unlock with your password.
              {lockStatus?.prefer_os_auth ? " OS authentication is preferred when available." : ""}
            </p>
            {lockStatus?.os_auth_available ? (
              <div className="actions">
                <button type="button" className="primary" disabled={unlockBusy} onClick={() => void onTryOsAuth()}>
                  Use OS authentication
                </button>
              </div>
            ) : lockStatus?.prefer_os_auth ? (
              <p className="muted">OS authentication: {lockStatus.os_auth_method || "unavailable"}. Use your password.</p>
            ) : null}
            <label className="field-label" htmlFor="unlock-password">Password</label>
            <input
              id="unlock-password"
              type="password"
              value={unlockPassword}
              onChange={(e) => setUnlockPassword(e.target.value)}
              autoComplete="current-password"
              autoFocus
              disabled={unlockBusy}
            />
            {unlockError ? <p className="error" role="alert">{unlockError}</p> : null}
            <div className="actions">
              <button type="submit" className="primary" disabled={unlockBusy || !unlockPassword}>
                {unlockBusy ? "Unlocking…" : "Unlock"}
              </button>
            </div>
          </form>
        </div>
      ) : null}
      <main className={`app${locked ? " app-locked" : ""}`} aria-hidden={locked || undefined}>
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
          <button type="button" onClick={() => void openLogs()} aria-haspopup="dialog" title="Logs">
            Logs
          </button>
          <button type="button" onClick={() => void openSettings()} aria-haspopup="dialog" title="Settings">
            Settings
          </button>
          <button type="button" onClick={() => void openAbout()} aria-haspopup="dialog" title="About">
            About
          </button>
        </nav>
      </header>

      <section className={`card status status-${status?.state ?? "unknown"} ${reachable ? "" : "unreachable"} ${status?.state === "bootstrapping" || status?.state === "starting" ? "status-animating" : ""}`}>
        <div className="status-header">
          <StatusIcon state={status?.state} reachable={reachable} size={28} />
          <div className="status-title-group">
            <p className="headline">{headline}</p>
            {reachable ? (
              (() => {
                const badgeLabel =
                  status?.state === "connected" || status?.state === "serving"
                    ? "Connected"
                    : status?.state === "bootstrapping"
                      ? "Bootstrapping"
                      : status?.state === "starting"
                        ? "Starting"
                        : status?.state === "stopping"
                          ? "Stopping"
                          : status?.state === "stopped"
                            ? "Stopped"
                            : status?.state === "error"
                              ? "Error"
                              : "Unknown";
                const headlineLower = headline.toLowerCase();
                const badgeLower = badgeLabel.toLowerCase();
                if (headlineLower === badgeLower || headlineLower === `${badgeLower}…` || headlineLower.startsWith(badgeLower)) {
                  return null;
                }
                return <span className={`status-badge status-badge-${status?.state ?? "unknown"}`}>{badgeLabel}</span>;
              })()
            ) : (
              <span className="status-badge status-badge-unreachable">Offline</span>
            )}
          </div>
        </div>
        {!reachable ? (
          <p className="muted" style={{ marginTop: 0 }}>
            If the local <code>tobrod</code> daemon is not running, Tobro will try to start it automatically when you connect.
          </p>
        ) : null}
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
        <ConnectionInfo status={status} reachable={reachable} connectedAt={connectedAt} />
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
      </main>
    </>
  );
}
