import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useRef, useState } from "react";
import { LogViewer, type LogEntry } from "./LogViewer";

interface TobroEvent {
  kind: string;
  payload: unknown;
}

interface BootstrapProgress {
  percent?: number;
  detail?: string;
}

export interface LogsProps {
  onClose: () => void;
}

export function Logs({ onClose }: LogsProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const nextLogId = useRef(1);

  function appendLog(
    text: string,
    level: "info" | "error" = "info",
    source?: string,
  ) {
    const entry: LogEntry = {
      id: nextLogId.current++,
      ts: new Date().toISOString(),
      text,
      level,
      source,
    };
    setLogs((prev) => [...prev.slice(-999), entry]);
  }

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    (async () => {
      unlisten = await listen<TobroEvent>("tobro-event", (event) => {
        const { kind, payload } = event.payload;
        if (kind === "status") return;
        if (kind === "reachable") {
          const p = payload as { socket?: string };
          if (p?.socket)
            appendLog(`daemon reachable (${p.socket})`, "info", "daemon");
          else appendLog("daemon reachable", "info", "daemon");
          return;
        }
        if (kind === "hello") {
          const h = payload as {
            daemon_version?: string;
            rpc_version?: number;
            platform?: string;
            arti_version?: string;
          };
          appendLog(
            `daemon ${h.daemon_version ?? "?"} (rpc v${h.rpc_version ?? "?"}, ${h.platform ?? "?"}, arti ${h.arti_version ?? "?"})`,
            "info",
            "daemon",
          );
          return;
        }
        if (kind === "unreachable") {
          const p = payload as { error?: string };
          if (p?.error) appendLog(p.error, "error", "daemon");
          else appendLog("daemon unreachable", "error", "daemon");
          return;
        }
        if (kind === "ui.log") {
          const p = payload as {
            text?: string;
            level?: "info" | "error";
            source?: string;
          };
          if (p?.text)
            appendLog(p.text, p.level === "error" ? "error" : "info", p.source);
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
            appendLog(
              `state → ${s.state ?? "?"}${detail}`,
              s.state === "error" ? "error" : "info",
              "daemon",
            );
          } else if (e.method) {
            appendLog(e.method, "info", "daemon");
          }
        }
      });
    })();
    appendLog(
      "Log window opened. Live daemon events will appear here.",
      "info",
      "ui",
    );
    return () => {
      if (unlisten) void unlisten();
    };
  }, []);

  return (
    <LogViewer
      title="Logs"
      entries={logs}
      onClear={() => setLogs([])}
      onClose={onClose}
      collapsible={false}
      defaultOpen={true}
      className="logs-window-viewer"
    />
  );
}
