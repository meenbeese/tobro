import { useMemo, useState } from "react";
import { redactLogText } from "./logRedaction";

export type LogLevel = "info" | "error";

export interface LogEntry {
  id: number;
  ts: string;
  text: string;
  level: LogLevel;
  source?: string;
}

type LevelFilter = "all" | LogLevel;

export interface LogViewerProps {
  entries: LogEntry[];
  onClear?: () => void;
  className?: string;
}

function formatStamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour12: false });
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function serializeEntries(entries: LogEntry[], redacted: boolean): string {
  const lines = entries.map((e) => {
    const text = redacted ? redactLogText(e.text) : e.text;
    const src = e.source ? ` ${e.source}` : "";
    return `[${e.ts}] [${e.level.toUpperCase()}]${src} ${text}`;
  });
  const header = [
    "# tobro event log",
    `# exported: ${new Date().toISOString()}`,
    `# entries: ${entries.length}`,
    `# redaction: ${redacted ? "applied (defense-in-depth)" : "not applied"}`,
    "",
  ];
  return `${header.join("\n")}${lines.join("\n")}\n`;
}

export function LogViewer({ entries, onClear, className }: LogViewerProps) {
  const [open, setOpen] = useState(true);
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState<LevelFilter>("all");
  const [applyRedaction, setApplyRedaction] = useState(true);
  const [message, setMessage] = useState<string>("");
  const [error, setError] = useState<string>("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => {
      if (level !== "all" && e.level !== level) return false;
      if (!q) return true;
      return e.text.toLowerCase().includes(q) || e.level.includes(q);
    });
  }, [entries, query, level]);

  const displayEntries = useMemo(
    () =>
      filtered.map((e) => ({
        ...e,
        displayText: applyRedaction ? redactLogText(e.text) : e.text,
      })),
    [filtered, applyRedaction],
  );

  async function onCopy() {
    setError("");
    setMessage("");
    try {
      const text = serializeEntries(filtered, applyRedaction);
      await navigator.clipboard.writeText(text);
      setMessage(`Copied ${filtered.length} entr${filtered.length === 1 ? "y" : "ies"}.`);
    } catch (e) {
      setError(`Copy failed: ${String(e)}`);
    }
  }

  function onSave() {
    setError("");
    setMessage("");
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      downloadText(`tobro-logs-${stamp}.txt`, serializeEntries(filtered, applyRedaction));
      setMessage(`Saved ${filtered.length} entr${filtered.length === 1 ? "y" : "ies"}.`);
    } catch (e) {
      setError(`Save failed: ${String(e)}`);
    }
  }

  function onClearClick() {
    setMessage("");
    setError("");
    onClear?.();
  }

  return (
    <section className={`card logs ${open ? "open" : "collapsed"} ${className ?? ""}`.trim()}>
      <div className="logs-header">
        <h2>Log</h2>
        <div className="logs-header-actions">
          <span className="muted logs-count" aria-live="polite">
            {filtered.length === entries.length
              ? `${entries.length}`
              : `${filtered.length}/${entries.length}`}
          </span>
          <button
            type="button"
            className="logs-toggle"
            aria-expanded={open}
            aria-controls="event-log-panel"
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide" : "Show"}
          </button>
        </div>
      </div>

      {open ? (
        <div id="event-log-panel">
          <div className="log-controls" role="group" aria-label="Log filters and actions">
            <label className="log-control">
              <span className="sr-only">Filter by text</span>
              <input
                type="search"
                placeholder="Filter logs…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Filter logs"
              />
            </label>
            <label className="log-control">
              <span className="sr-only">Filter by level</span>
              <select value={level} onChange={(e) => setLevel(e.target.value as LevelFilter)} aria-label="Log level filter">
                <option value="all">All levels</option>
                <option value="info">Info</option>
                <option value="error">Errors</option>
              </select>
            </label>
            <label className="log-control log-check">
              <input
                type="checkbox"
                checked={applyRedaction}
                onChange={(e) => setApplyRedaction(e.target.checked)}
              />
              Redact on copy/save/display
            </label>
            <div className="log-actions">
              <button type="button" onClick={() => void onCopy()} disabled={filtered.length === 0}>
                Copy
              </button>
              <button type="button" onClick={onSave} disabled={filtered.length === 0}>
                Save
              </button>
              {onClear ? (
                <button type="button" onClick={onClearClick} disabled={entries.length === 0}>
                  Clear
                </button>
              ) : null}
            </div>
          </div>

          {message ? <p className="muted log-message">{message}</p> : null}
          {error ? <p className="error log-message">{error}</p> : null}

          <ol className="log-list" aria-label="Event log">
            {displayEntries.length === 0 ? (
              <li className="muted">{entries.length === 0 ? "No events yet." : "No matching events."}</li>
            ) : null}
            {displayEntries.map((entry) => (
              <li key={entry.id} className={`log-line ${entry.level === "error" ? "error" : ""}`}>
                <span className="log-ts">{formatStamp(entry.ts)}</span>
                <span className="log-level">[{entry.level}]</span>
                <span className="log-text">{entry.displayText}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </section>
  );
}
