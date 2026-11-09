import { useEffect, useMemo, useRef, useState } from "react";
import { redactLogText } from "./logRedaction";

const PREF_REDACT = "tobro.logViewer.redact";
const PREF_WRAP = "tobro.logViewer.wrap";

function readBoolPref(key: string, fallback: boolean): boolean {
  try {
    const value = localStorage.getItem(key);
    if (value === "true") return true;
    if (value === "false") return false;
  } catch {
    // ignore
  }
  return fallback;
}

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
  onClose?: () => void;
  defaultOpen?: boolean;
  collapsible?: boolean;
  title?: string;
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

export function LogViewer({
  entries,
  onClear,
  onClose,
  defaultOpen = false,
  collapsible = true,
  title = "Log",
  className,
}: LogViewerProps) {
  const [open, setOpen] = useState(collapsible ? defaultOpen : true);
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState<LevelFilter>("all");
  const [applyRedaction, setApplyRedaction] = useState(() =>
    readBoolPref(PREF_REDACT, true),
  );
  const [wrapLines, setWrapLines] = useState(() =>
    readBoolPref(PREF_WRAP, true),
  );
  const [message, setMessage] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [pinnedToBottom, setPinnedToBottom] = useState(true);
  const [hasNewWhilePaused, setHasNewWhilePaused] = useState(false);
  const logListRef = useRef<HTMLOListElement | null>(null);
  const lastSeenCountRef = useRef(0);
  const programmaticScrollRef = useRef(false);
  const isOpen = collapsible ? open : true;

  useEffect(() => {
    try {
      localStorage.setItem(PREF_REDACT, String(applyRedaction));
    } catch {
      // ignore
    }
  }, [applyRedaction]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_WRAP, String(wrapLines));
    } catch {
      // ignore
    }
  }, [wrapLines]);

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

  function isNearBottom(el: HTMLElement, threshold = 32): boolean {
    return el.scrollHeight - el.scrollTop - el.clientHeight <= threshold;
  }

  function scrollToLatest(behavior: ScrollBehavior = "auto") {
    const el = logListRef.current;
    if (!el) return;
    programmaticScrollRef.current = true;
    el.scrollTo({ top: el.scrollHeight, behavior });
    setPinnedToBottom(true);
    setHasNewWhilePaused(false);
    lastSeenCountRef.current = displayEntries.length;
    window.requestAnimationFrame(() => {
      programmaticScrollRef.current = false;
    });
  }

  function onLogScroll() {
    const el = logListRef.current;
    if (!el || programmaticScrollRef.current) return;
    const near = isNearBottom(el);
    setPinnedToBottom(near);
    if (near) {
      setHasNewWhilePaused(false);
      lastSeenCountRef.current = displayEntries.length;
    }
  }

  useEffect(() => {
    if (!isOpen) return;
    const el = logListRef.current;
    if (!el) return;
    const count = displayEntries.length;
    if (pinnedToBottom) {
      if (
        count !== lastSeenCountRef.current ||
        el.scrollHeight > el.clientHeight
      ) {
        scrollToLatest("auto");
      } else {
        lastSeenCountRef.current = count;
      }
      return;
    }
    if (count > lastSeenCountRef.current) {
      setHasNewWhilePaused(true);
    }
  }, [displayEntries.length, isOpen, pinnedToBottom]);

  useEffect(() => {
    if (isOpen && pinnedToBottom) {
      scrollToLatest("auto");
    }
  }, [isOpen]);

  async function onCopy() {
    setError("");
    setMessage("");
    try {
      const text = serializeEntries(filtered, applyRedaction);
      await navigator.clipboard.writeText(text);
      setMessage(
        `Copied ${filtered.length} entr${filtered.length === 1 ? "y" : "ies"}.`,
      );
    } catch (e) {
      setError(`Copy failed: ${String(e)}`);
    }
  }

  function onSave() {
    setError("");
    setMessage("");
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      downloadText(
        `tobro-logs-${stamp}.txt`,
        serializeEntries(filtered, applyRedaction),
      );
      setMessage(
        `Saved ${filtered.length} entr${filtered.length === 1 ? "y" : "ies"}.`,
      );
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
    <section
      className={`card logs ${isOpen ? "open" : "collapsed"} ${className ?? ""}`.trim()}
    >
      <div className="logs-header">
        <h2>{title}</h2>
        <div className="logs-header-actions">
          <span className="muted logs-count" aria-live="polite">
            {filtered.length === entries.length
              ? `${entries.length}`
              : `${filtered.length}/${entries.length}`}
          </span>
          {collapsible ? (
            <button
              type="button"
              className="logs-toggle"
              aria-expanded={open}
              aria-controls="event-log-panel"
              onClick={() => setOpen((v) => !v)}
            >
              {open ? "Hide" : "Show"}
            </button>
          ) : null}
        </div>
      </div>

      {isOpen ? (
        <div id="event-log-panel">
          <div
            className="log-controls"
            role="group"
            aria-label="Log filters and actions"
          >
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
              <select
                value={level}
                onChange={(e) => setLevel(e.target.value as LevelFilter)}
                aria-label="Log level filter"
              >
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
              Redact
            </label>
            <label className="log-control log-check">
              <input
                type="checkbox"
                checked={wrapLines}
                onChange={(e) => setWrapLines(e.target.checked)}
              />
              Wrap
            </label>
            <div className="log-actions">
              <button
                type="button"
                onClick={() => void onCopy()}
                disabled={filtered.length === 0}
              >
                Copy
              </button>
              <button
                type="button"
                onClick={onSave}
                disabled={filtered.length === 0}
              >
                Save
              </button>
              {onClear ? (
                <button
                  type="button"
                  onClick={onClearClick}
                  disabled={entries.length === 0}
                >
                  Clear
                </button>
              ) : null}
              {onClose ? (
                <button type="button" onClick={onClose}>
                  Close
                </button>
              ) : null}
            </div>
          </div>

          {message ? <p className="muted log-message">{message}</p> : null}
          {error ? <p className="error log-message">{error}</p> : null}

          {!pinnedToBottom && displayEntries.length > 0 ? (
            <div className="log-jump">
              <button type="button" onClick={() => scrollToLatest("smooth")}>
                {hasNewWhilePaused ? "Jump to latest (new)" : "Jump to latest"}
              </button>
            </div>
          ) : null}

          <ol
            ref={logListRef}
            onScroll={onLogScroll}
            className={`log-list ${wrapLines ? "wrap" : "nowrap"}`}
            aria-label="Event log"
          >
            {displayEntries.length === 0 ? (
              <li className="muted log-empty">
                {entries.length === 0
                  ? "No events yet. Connect to the daemon or perform an action to see status events here."
                  : "No events match the current filters."}
              </li>
            ) : null}
            {displayEntries.map((entry) => (
              <li
                key={entry.id}
                className={`log-line ${entry.level === "error" ? "error" : ""}`}
              >
                <span className="log-ts" title={entry.ts}>
                  {formatStamp(entry.ts)}
                </span>
                <span
                  className={`log-level ${entry.level === "error" ? "error" : "info"}`}
                >
                  [{entry.level}]
                </span>
                <span className={`log-source ${entry.source ? "" : "empty"}`}>
                  {entry.source ?? ""}
                </span>
                <span className="log-text">{entry.displayText}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </section>
  );
}
