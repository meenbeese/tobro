import { invoke } from "@tauri-apps/api/core";
import { useRef, useState, type ChangeEvent } from "react";

interface ConfigEffects {
  restart_required?: boolean;
  listeners_changed?: boolean;
  runtime_active?: boolean;
  warnings?: string[];
}

interface ConfigResponse {
  ok?: boolean;
  path?: string;
  config?: unknown;
  valid?: boolean;
  saved?: boolean;
  effects?: ConfigEffects;
  proxy?: unknown;
  action?: string;
}

function downloadJson(filename: string, value: unknown) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
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

function parsePatch(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Paste or load a JSON config patch/object first.");
  const parsed = JSON.parse(trimmed) as unknown;
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && "patch" in (parsed as Record<string, unknown>)) {
    const inner = (parsed as Record<string, unknown>).patch;
    if (inner && typeof inner === "object" && !Array.isArray(inner)) return inner;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Config import must be a JSON object (a config patch or config object).");
  }
  return parsed;
}

function summarizeEffects(effects?: ConfigEffects): string[] {
  if (!effects) return [];
  const lines: string[] = [];
  if (effects.listeners_changed) lines.push("Listener settings changed.");
  if (effects.restart_required) {
    lines.push(
      effects.runtime_active
        ? "Restart required for active runtime/listeners: use Stop then Connect after applying."
        : "Changes apply on the next connection/start.",
    );
  } else if (!effects.listeners_changed) {
    lines.push("No listener restart flagged by validation.");
  }
  if (effects.warnings?.length) {
    for (const w of effects.warnings) lines.push(`Warning: ${w}`);
  }
  return lines;
}

export interface ConfigPanelProps {
  onClose: () => void;
  onApplied?: () => void;
  appendLog?: (text: string, level?: "info" | "error", source?: string) => void;
}

export function ConfigPanel({ onClose, onApplied, appendLog }: ConfigPanelProps) {
  const [busy, setBusy] = useState(false);
  const [configPath, setConfigPath] = useState<string>("");
  const [currentConfig, setCurrentConfig] = useState<unknown>(null);
  const [importText, setImportText] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [error, setError] = useState<string>("");
  const fileRef = useRef<HTMLInputElement | null>(null);

  function log(text: string, level: "info" | "error" = "info") {
    appendLog?.(text, level, "ui");
  }

  async function onRefresh() {
    setBusy(true);
    setError("");
    try {
      const result = await invoke<ConfigResponse>("daemon_get_config");
      setCurrentConfig(result.config ?? null);
      setConfigPath(typeof result.path === "string" ? result.path : "");
      setMessages(["Loaded current daemon config (redacted; no secrets)."]);
      log("config: loaded current config");
    } catch (e) {
      setError(String(e));
      log(`config: load failed: ${String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  function onExport() {
    setError("");
    if (!currentConfig) {
      setError("Load the current config first.");
      return;
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadJson(`tobro-config-redacted-${stamp}.json`, currentConfig);
    setMessages(["Exported redacted config JSON (no secrets)."]);
    log("config: exported redacted config");
  }

  async function onCopyCurrent() {
    setError("");
    if (!currentConfig) {
      setError("Load the current config first.");
      return;
    }
    try {
      await navigator.clipboard.writeText(`${JSON.stringify(currentConfig, null, 2)}\n`);
      setMessages(["Copied current redacted config to clipboard."]);
    } catch (e) {
      setError(`Copy failed: ${String(e)}`);
    }
  }

  async function onPickFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setImportText(text);
      setError("");
      setMessages([`Loaded ${file.name}. Review, then Validate or Apply.`]);
    } catch (err) {
      setError(`Could not read file: ${String(err)}`);
    } finally {
      e.target.value = "";
    }
  }

  async function onValidate() {
    setBusy(true);
    setError("");
    setMessages([]);
    try {
      const patch = parsePatch(importText);
      const result = await invoke<ConfigResponse>("daemon_validate_config", { patch });
      const lines = ["Validation succeeded. No changes were saved."];
      if (typeof result.path === "string") lines.push(`Path: ${result.path}`);
      lines.push(...summarizeEffects(result.effects));
      setMessages(lines);
      log("config: validation succeeded");
    } catch (e) {
      setError(String(e));
      log(`config: validation failed: ${String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  async function onApply() {
    setBusy(true);
    setError("");
    setMessages([]);
    try {
      const patch = parsePatch(importText);
      const result = await invoke<ConfigResponse>("daemon_apply_config", { patch });
      if (result.config) setCurrentConfig(result.config);
      if (typeof result.path === "string") setConfigPath(result.path);
      const lines = ["Config validated and saved (daemon config API)."];
      lines.push(...summarizeEffects(result.effects));
      lines.push("Redacted config contains no secrets; secrets remain in the OS keychain/store when used.");
      setMessages(lines);
      log("config: applied");
      onApplied?.();
    } catch (e) {
      setError(String(e));
      log(`config: apply failed: ${String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card config-panel" aria-label="Configuration import and export">
      <div className="panel-header">
        <div>
          <h2>Config import/export</h2>
          <p className="muted">
            Uses the daemon config API. Exports are <strong>redacted</strong> and contain <strong>no secrets</strong>.
            Import accepts a JSON object/patch; validate before applying.
          </p>
        </div>
        <button type="button" className="logs-toggle" onClick={onClose}>Close</button>
      </div>

      <div className="config-actions">
        <button type="button" onClick={() => void onRefresh()} disabled={busy}>Load current</button>
        <button type="button" onClick={onExport} disabled={busy || !currentConfig}>Export JSON</button>
        <button type="button" onClick={() => void onCopyCurrent()} disabled={busy || !currentConfig}>Copy current</button>
      </div>
      {configPath ? <p className="muted config-hint">Config path: <code>{configPath}</code></p> : null}

      <details className="config-preview" open={Boolean(currentConfig)}>
        <summary>Current config (redacted)</summary>
        <pre>{currentConfig ? JSON.stringify(currentConfig, null, 2) : "Load the current config to preview it."}</pre>
      </details>

      <div className="config-import">
        <h3>Import / apply JSON patch</h3>
        <p className="muted">
          Paste a JSON object (config patch). It is merged, validated (<code>deny_unknown_fields</code>), and only saved/applied if valid.
        </p>
        <div className="config-actions">
          <button type="button" onClick={() => fileRef.current?.click()} disabled={busy}>Load file…</button>
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            className="sr-only"
            onChange={(e) => void onPickFile(e)}
          />
          <button type="button" onClick={() => void onValidate()} disabled={busy || !importText.trim()}>Validate</button>
          <button type="button" className="primary" onClick={() => void onApply()} disabled={busy || !importText.trim()}>Apply</button>
        </div>
        <label className="sr-only" htmlFor="config-import-text">Config JSON patch</label>
        <textarea
          id="config-import-text"
          className="config-textarea"
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder={'{\n  "proxy": { "socks_port": 9050, "http_port": 9050, "dns_port": 9053 }\n}'}
          spellCheck={false}
          rows={10}
        />
      </div>

      {messages.length ? (
        <ul className="config-messages muted">
          {messages.map((m, i) => <li key={i}>{m}</li>)}
        </ul>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}
