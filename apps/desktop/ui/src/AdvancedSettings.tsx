import { invoke } from "@tauri-apps/api/core";
import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";

const POWER_USER_KEY = "tobro.powerUser.enabled";

function readPowerUser(): boolean {
  try {
    return localStorage.getItem(POWER_USER_KEY) === "true";
  } catch {
    return false;
  }
}

function writePowerUser(value: boolean) {
  try {
    localStorage.setItem(POWER_USER_KEY, String(value));
  } catch {
    // ignore
  }
}

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
}

interface ProxyPorts {
  socks_port: number;
  http_port: number;
  dns_port: number;
  config_path?: string;
}

type PortField = "socks_port" | "http_port" | "dns_port";

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

function parsePort(value: string): number | null {
  if (!/^\d+$/.test(value)) return null;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return port;
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

export interface AdvancedSettingsProps {
  onClose: () => void;
  onApplied?: () => void;
  appendLog?: (text: string, level?: "info" | "error", source?: string) => void;
}

export function AdvancedSettings({ onClose, onApplied, appendLog }: AdvancedSettingsProps) {
  const [powerUser, setPowerUser] = useState(readPowerUser);
  const [busy, setBusy] = useState(false);

  // Listener ports
  const [portInputs, setPortInputs] = useState<Record<PortField, string>>({
    socks_port: "9050",
    http_port: "9050",
    dns_port: "9053",
  });
  const [portsDirty, setPortsDirty] = useState(false);
  const [portsBusy, setPortsBusy] = useState(false);
  const [portsMessage, setPortsMessage] = useState("");
  const [portsError, setPortsError] = useState("");

  // Config import/export
  const [configPath, setConfigPath] = useState("");
  const [currentConfig, setCurrentConfig] = useState<unknown>(null);
  const [importText, setImportText] = useState("");
  const [configMessages, setConfigMessages] = useState<string[]>([]);
  const [configError, setConfigError] = useState("");
  const fileRef = useRef<HTMLInputElement | null>(null);

  function log(text: string, level: "info" | "error" = "info") {
    appendLog?.(text, level, "ui");
  }

  async function loadPorts() {
    try {
      const loaded = await invoke<ProxyPorts>("get_proxy_ports");
      setPortInputs({
        socks_port: String(loaded.socks_port),
        http_port: String(loaded.http_port),
        dns_port: String(loaded.dns_port),
      });
      if (loaded.config_path) setConfigPath(loaded.config_path);
      setPortsDirty(false);
      setPortsError("");
    } catch (e) {
      setPortsError(String(e));
    }
  }

  useEffect(() => {
    if (powerUser) void loadPorts();
  }, [powerUser]);

  function enablePowerUser() {
    writePowerUser(true);
    setPowerUser(true);
    log("advanced settings enabled (power-user gate acknowledged)");
  }

  function disablePowerUser() {
    writePowerUser(false);
    setPowerUser(false);
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

  async function onSavePorts(e: FormEvent) {
    e.preventDefault();
    const socksPort = parsePort(portInputs.socks_port);
    const httpPortRaw = parsePort(portInputs.http_port);
    const dnsPort = parsePort(portInputs.dns_port);
    const httpPort = portInputs.http_port.trim() === "0" ? 0 : httpPortRaw;
    if (socksPort === null || dnsPort === null || httpPort === null) {
      setPortsError("Ports must be integers: SOCKS/DNS 1–65535, HTTP 0–65535 (0 follows SOCKS).");
      return;
    }
    setPortsBusy(true);
    setPortsError("");
    setPortsMessage("");
    try {
      const result = await invoke<{
        proxy?: ProxyPorts;
        reload?: { apply?: string; warnings?: string[] } | null;
        config_path?: unknown;
      }>("save_proxy_ports", { socksPort, httpPort, dnsPort });
      if (result.proxy) {
        setPortInputs({
          socks_port: String(result.proxy.socks_port),
          http_port: String(result.proxy.http_port),
          dns_port: String(result.proxy.dns_port),
        });
        if (result.proxy.config_path) setConfigPath(result.proxy.config_path);
      } else if (typeof result.config_path === "string") {
        setConfigPath(result.config_path);
      }
      setPortsDirty(false);
      const apply = result.reload?.apply;
      const warnings = result.reload?.warnings ?? [];
      const msg = apply ? `Saved. ${apply}` : "Saved to config.";
      setPortsMessage(warnings.length ? `${msg} Warnings: ${warnings.join(" | ")}` : msg);
      log(`ports saved (SOCKS ${socksPort}, HTTP ${httpPort || socksPort}, DNS ${dnsPort})`);
      if (warnings.length) log(warnings.join(" | "), "error");
      onApplied?.();
    } catch (err) {
      const message = String(err);
      setPortsError(message);
      log(message, "error");
    } finally {
      setPortsBusy(false);
    }
  }

  async function onRefreshConfig() {
    setBusy(true);
    setConfigError("");
    try {
      const result = await invoke<ConfigResponse>("daemon_get_config");
      setCurrentConfig(result.config ?? null);
      if (typeof result.path === "string") setConfigPath(result.path);
      setConfigMessages(["Loaded current daemon config (redacted; no secrets)."]);
      log("config: loaded current config");
    } catch (e) {
      setConfigError(String(e));
      log(`config: load failed: ${String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  function onExport() {
    setConfigError("");
    if (!currentConfig) {
      setConfigError("Load the current config first.");
      return;
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadJson(`tobro-config-redacted-${stamp}.json`, currentConfig);
    setConfigMessages(["Exported redacted config JSON (no secrets)."]);
    log("config: exported redacted config");
  }

  async function onCopyCurrent() {
    setConfigError("");
    if (!currentConfig) {
      setConfigError("Load the current config first.");
      return;
    }
    try {
      await navigator.clipboard.writeText(`${JSON.stringify(currentConfig, null, 2)}\n`);
      setConfigMessages(["Copied current redacted config to clipboard."]);
    } catch (e) {
      setConfigError(`Copy failed: ${String(e)}`);
    }
  }

  async function onPickFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setImportText(text);
      setConfigError("");
      setConfigMessages([`Loaded ${file.name}. Review, then Validate or Apply.`]);
    } catch (err) {
      setConfigError(`Could not read file: ${String(err)}`);
    } finally {
      e.target.value = "";
    }
  }

  async function onValidate() {
    setBusy(true);
    setConfigError("");
    setConfigMessages([]);
    try {
      const patch = parsePatch(importText);
      const result = await invoke<ConfigResponse>("daemon_validate_config", { patch });
      const lines = ["Validation succeeded. No changes were saved."];
      if (typeof result.path === "string") lines.push(`Path: ${result.path}`);
      lines.push(...summarizeEffects(result.effects));
      setConfigMessages(lines);
      log("config: validation succeeded");
    } catch (e) {
      setConfigError(String(e));
      log(`config: validation failed: ${String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  async function onApplyConfig() {
    setBusy(true);
    setConfigError("");
    setConfigMessages([]);
    try {
      const patch = parsePatch(importText);
      const result = await invoke<ConfigResponse>("daemon_apply_config", { patch });
      if (result.config) setCurrentConfig(result.config);
      if (typeof result.path === "string") setConfigPath(result.path);
      const lines = ["Config validated and saved (daemon config API)."];
      lines.push(...summarizeEffects(result.effects));
      lines.push("Redacted config contains no secrets; secrets remain in the OS keychain/store when used.");
      setConfigMessages(lines);
      log("config: applied");
      await loadPorts();
      onApplied?.();
    } catch (e) {
      setConfigError(String(e));
      log(`config: apply failed: ${String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card advanced-settings" aria-label="Advanced settings">
      <div className="panel-header">
        <div>
          <h2>Advanced settings</h2>
          <p className="muted">Power-user controls. Unsupported options are hidden rather than silently ignored.</p>
        </div>
        <button type="button" className="logs-toggle" onClick={onClose}>Close</button>
      </div>

      {!powerUser ? (
        <div className="power-user-gate" role="alert">
          <h3>Power-user gate</h3>
          <p>
            Advanced settings can affect connectivity, leak local services if misconfigured, or require a restart of Tor listeners.
            Only change them if you understand the impact.
          </p>
          <ul className="muted">
            <li>Listener port changes may conflict with other apps and can require Stop → Connect.</li>
            <li>Config import/export is validated, but applying the wrong config can break startup/connect behavior.</li>
            <li>Config exports are redacted and contain no secrets; secrets remain in the OS keychain/store.</li>
          </ul>
          <div className="actions">
            <button type="button" className="primary" onClick={enablePowerUser}>I understand, enable advanced settings</button>
            <button type="button" onClick={onClose}>Cancel</button>
          </div>
        </div>
      ) : (
        <div className="advanced-sections">
          <div className="settings-section-head">
            <p className="muted">Power-user mode is enabled for this UI profile.</p>
            <button type="button" className="logs-toggle" onClick={disablePowerUser}>Lock advanced settings</button>
          </div>

          <form className="settings-section port-editor" onSubmit={onSavePorts}>
            <h3>Listener ports</h3>
            <p className="muted">
              Configure local SOCKS/HTTP and DNS ports. With the current Arti backend, SOCKS and HTTP share one listener, so HTTP should match SOCKS (use <code>0</code> to follow SOCKS). Active listener changes require stop/connect.
            </p>
            <div className="port-grid">
              <label>
                SOCKS
                <input type="number" min={1} max={65535} inputMode="numeric" value={portInputs.socks_port} onChange={(e) => updatePort("socks_port", e.target.value)} />
              </label>
              <label>
                HTTP
                <input type="number" min={0} max={65535} inputMode="numeric" value={portInputs.http_port} onChange={(e) => updatePort("http_port", e.target.value)} />
              </label>
              <label>
                DNS
                <input type="number" min={1} max={65535} inputMode="numeric" value={portInputs.dns_port} onChange={(e) => updatePort("dns_port", e.target.value)} />
              </label>
            </div>
            {configPath ? <p className="muted config-hint">Config: <code>{configPath}</code></p> : null}
            {portsError ? <p className="error">{portsError}</p> : null}
            {portsMessage ? <p className="muted">{portsMessage}</p> : null}
            <div className="actions">
              <button className="primary" type="submit" disabled={portsBusy || !portsDirty}>{portsBusy ? "Saving…" : "Save ports"}</button>
              <button type="button" onClick={() => void loadPorts()} disabled={portsBusy}>Reset</button>
            </div>
          </form>

          <div className="settings-section config-import">
            <h3>Config import/export (no secrets)</h3>
            <p className="muted">
              Uses the daemon config API. Exports are <strong>redacted</strong> and contain <strong>no secrets</strong>. Import accepts a JSON object/patch; it is merged, validated (<code>deny_unknown_fields</code>), and only saved/applied if valid.
            </p>
            <div className="config-actions">
              <button type="button" onClick={() => void onRefreshConfig()} disabled={busy}>Load current</button>
              <button type="button" onClick={onExport} disabled={busy || !currentConfig}>Export JSON</button>
              <button type="button" onClick={() => void onCopyCurrent()} disabled={busy || !currentConfig}>Copy current</button>
            </div>
            {configPath ? <p className="muted config-hint">Config path: <code>{configPath}</code></p> : null}
            <details className="config-preview" open={Boolean(currentConfig)}>
              <summary>Current config (redacted)</summary>
              <pre>{currentConfig ? JSON.stringify(currentConfig, null, 2) : "Load the current config to preview it."}</pre>
            </details>
            <div className="config-actions">
              <button type="button" onClick={() => fileRef.current?.click()} disabled={busy}>Load file…</button>
              <input ref={fileRef} type="file" accept=".json,application/json" className="sr-only" onChange={(e) => void onPickFile(e)} />
              <button type="button" onClick={() => void onValidate()} disabled={busy || !importText.trim()}>Validate</button>
              <button type="button" className="primary" onClick={() => void onApplyConfig()} disabled={busy || !importText.trim()}>Apply</button>
            </div>
            <label className="sr-only" htmlFor="advanced-config-import-text">Config JSON patch</label>
            <textarea
              id="advanced-config-import-text"
              className="config-textarea"
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder={'{\n  "proxy": { "socks_port": 9050, "http_port": 9050, "dns_port": 9053 }\n}'}
              spellCheck={false}
              rows={10}
            />
            {configMessages.length ? (
              <ul className="config-messages muted">
                {configMessages.map((m, i) => <li key={i}>{m}</li>)}
              </ul>
            ) : null}
            {configError ? <p className="error">{configError}</p> : null}
          </div>
        </div>
      )}
    </section>
  );
}
