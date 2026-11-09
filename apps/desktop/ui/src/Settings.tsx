import { invoke } from "@tauri-apps/api/core";
import { useEffect, useRef, useState, type ChangeEvent, type FormEvent, type KeyboardEvent } from "react";
import { readThemePreference, setThemePreference, type ThemePreference } from "./theme";
import { readCaptureProtectionEnabled, setCaptureProtectionEnabled } from "./captureProtection";

const POWER_USER_KEY = "tobro.powerUser.enabled";

const HELP_LINKS = [
  { label: "Tor Project support & docs", url: "https://support.torproject.org/" },
  { label: "Arti (Tor in Rust)", url: "https://gitlab.torproject.org/tpo/core/arti" },
  { label: "Tauri documentation", url: "https://tauri.app/" },
];

async function openExternal(url: string) {
  try {
    await invoke("open_external_url", { url });
  } catch {
    // ignore
  }
}

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
  stream_changed?: boolean;
  network_changed?: boolean;
  runtime_active?: boolean;
  warnings?: string[];
}

interface StreamSettings {
  isolate_destination: boolean;
  isolate_port: boolean;
  isolate_protocol: boolean;
  keep_alive_isolation: boolean;
}

type IpVersion = "ipv4_preferred" | "ipv6_preferred" | "ipv4_only" | "ipv6_only";

interface NetworkSettings {
  exit_country: string;
  ip_version: IpVersion;
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
  bind_all_interfaces?: boolean;
  config_path?: string;
}

type PortField = "socks_port" | "http_port" | "dns_port";

const BIND_ALL_WARNING =
  "Binding listeners to all interfaces exposes SOCKS, HTTP CONNECT, and DNS to other devices on reachable networks. " +
  "Other hosts may be able to route traffic through Tor from this machine. Only enable on trusted networks, " +
  "and configure your OS/router firewall to restrict access to these ports. Disable bind-all when not needed.";

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
  if (effects.stream_changed) lines.push("Stream isolation settings changed.");
  if (effects.network_changed) lines.push("Network/StreamPrefs defaults changed.");
  if (effects.restart_required) {
    lines.push(
      effects.runtime_active
        ? "Restart required for active runtime: use Stop then Connect after applying."
        : "Changes apply on the next connection/start.",
    );
  } else if (!effects.listeners_changed && !effects.stream_changed && !effects.network_changed) {
    lines.push("No restart flagged by validation.");
  }
  if (effects.warnings?.length) {
    for (const w of effects.warnings) lines.push(`Warning: ${w}`);
  }
  return lines;
}

export interface SettingsProps {
  onClose: () => void;
  onApplied?: () => void;
  appendLog?: (text: string, level?: "info" | "error", source?: string) => void;
}

export type AdvancedSettingsProps = SettingsProps;

type SettingsTab = "general" | "node" | "advanced";
const SETTINGS_TABS: { id: SettingsTab; label: string }[] = [
  { id: "general", label: "General" },
  { id: "node", label: "Node Configuration" },
  { id: "advanced", label: "Advanced Tor Configuration" },
];

export function Settings({ onClose, onApplied, appendLog }: SettingsProps) {
  const [powerUser, setPowerUser] = useState(readPowerUser);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<SettingsTab>("general");
  const [theme, setTheme] = useState<ThemePreference>(readThemePreference);
  const [captureProtection, setCaptureProtection] = useState(readCaptureProtectionEnabled);
  const tabRefs = useRef<Record<SettingsTab, HTMLButtonElement | null>>({
    general: null,
    node: null,
    advanced: null,
  });

  // Listener settings
  const [portInputs, setPortInputs] = useState<Record<PortField, string>>({
    socks_port: "9050",
    http_port: "9050",
    dns_port: "9053",
  });
  const [bindAllInterfaces, setBindAllInterfaces] = useState(false);
  const [portsDirty, setPortsDirty] = useState(false);
  const [portsBusy, setPortsBusy] = useState(false);
  const [portsMessage, setPortsMessage] = useState("");
  const [portsError, setPortsError] = useState("");

  // Stream isolation (F-42/F-43)
  const [stream, setStream] = useState<StreamSettings>({
    isolate_destination: false,
    isolate_port: false,
    isolate_protocol: false,
    keep_alive_isolation: false,
  });
  const [streamDirty, setStreamDirty] = useState(false);
  const [streamBusy, setStreamBusy] = useState(false);
  const [streamMessage, setStreamMessage] = useState("");
  const [streamError, setStreamError] = useState("");

  // Network/StreamPrefs defaults (M2)
  const [network, setNetwork] = useState<NetworkSettings>({
    exit_country: "",
    ip_version: "ipv4_preferred",
  });
  const [networkDirty, setNetworkDirty] = useState(false);
  const [networkBusy, setNetworkBusy] = useState(false);
  const [networkMessage, setNetworkMessage] = useState("");
  const [networkError, setNetworkError] = useState("");

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

  function applyStreamFromConfig(config: unknown) {
    const s = (config as { stream?: Partial<StreamSettings> } | null)?.stream;
    if (s && typeof s === "object") {
      setStream({
        isolate_destination: Boolean(s.isolate_destination),
        isolate_port: Boolean(s.isolate_port),
        isolate_protocol: Boolean(s.isolate_protocol),
        keep_alive_isolation: Boolean(s.keep_alive_isolation),
      });
      setStreamDirty(false);
      setStreamError("");
    }
  }

  function applyNetworkFromConfig(config: unknown) {
    const n = (config as { network?: Partial<NetworkSettings> & { exit_country?: string | null } } | null)?.network;
    if (n && typeof n === "object") {
      const ip = n.ip_version;
      const ip_version: IpVersion =
        ip === "ipv6_preferred" || ip === "ipv4_only" || ip === "ipv6_only" ? ip : "ipv4_preferred";
      setNetwork({
        exit_country: typeof n.exit_country === "string" ? n.exit_country : "",
        ip_version,
      });
      setNetworkDirty(false);
      setNetworkError("");
      setNetworkMessage("");
    }
  }

  async function loadPorts() {
    try {
      const loaded = await invoke<ProxyPorts>("get_proxy_ports");
      setPortInputs({
        socks_port: String(loaded.socks_port),
        http_port: String(loaded.http_port),
        dns_port: String(loaded.dns_port),
      });
      setBindAllInterfaces(Boolean(loaded.bind_all_interfaces));
      if (loaded.config_path) setConfigPath(loaded.config_path);
      setPortsDirty(false);
      setPortsError("");
    } catch (e) {
      setPortsError(String(e));
    }
  }

  async function loadConfigState() {
    try {
      const result = await invoke<ConfigResponse>("daemon_get_config");
      setCurrentConfig(result.config ?? null);
      if (typeof result.path === "string") setConfigPath(result.path);
      applyStreamFromConfig(result.config ?? null);
      applyNetworkFromConfig(result.config ?? null);
    } catch {
      // best-effort; listener loading may still work from local config
    }
  }

  useEffect(() => {
    if (powerUser) {
      void loadPorts();
      void loadConfigState();
    }
  }, [powerUser]);

  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  function onThemeChange(next: ThemePreference) {
    setTheme(next);
    setThemePreference(next);
    log(`theme set to ${next}`);
  }

  async function onCaptureProtectionChange(enabled: boolean) {
    setCaptureProtection(enabled);
    await setCaptureProtectionEnabled(enabled);
    log(`window capture protection ${enabled ? "enabled (best-effort)" : "disabled"}`);
  }

  function onTabKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const order = SETTINGS_TABS.map((t) => t.id);
    const idx = order.indexOf(tab);
    if (idx < 0) return;
    let nextIdx = idx;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % order.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + order.length) % order.length;
    else if (e.key === "Home") nextIdx = 0;
    else if (e.key === "End") nextIdx = order.length - 1;
    else return;
    e.preventDefault();
    const next = order[nextIdx];
    setTab(next);
    tabRefs.current[next]?.focus();
  }

  function enablePowerUser() {
    writePowerUser(true);
    setPowerUser(true);
    log("settings enabled (power-user gate acknowledged)");
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

  function onBindAllChange(enabled: boolean) {
    setPortsError("");
    setPortsMessage("");
    if (enabled && !bindAllInterfaces) {
      const confirmed = window.confirm(
        "Security warning: bind listeners to all interfaces?\n\n" +
          BIND_ALL_WARNING +
          "\n\nClick OK only if you understand the risk and have firewall rules in place.",
      );
      if (!confirmed) return;
      log("bind-all-interfaces opt-in acknowledged by user");
    }
    setBindAllInterfaces(enabled);
    setPortsDirty(true);
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
      }>("save_proxy_ports", { socksPort, httpPort, dnsPort, bindAllInterfaces });
      if (result.proxy) {
        setPortInputs({
          socks_port: String(result.proxy.socks_port),
          http_port: String(result.proxy.http_port),
          dns_port: String(result.proxy.dns_port),
        });
        setBindAllInterfaces(Boolean(result.proxy.bind_all_interfaces));
        if (result.proxy.config_path) setConfigPath(result.proxy.config_path);
      } else if (typeof result.config_path === "string") {
        setConfigPath(result.config_path);
      }
      setPortsDirty(false);
      const apply = result.reload?.apply;
      const warnings = result.reload?.warnings ?? [];
      const bind = bindAllInterfaces ? ", bind all interfaces" : "";
      const msg = apply ? `Saved. ${apply}` : "Saved to config.";
      setPortsMessage(warnings.length ? `${msg} Warnings: ${warnings.join(" | ")}` : msg);
      log(
        `listener settings saved (SOCKS ${socksPort}, HTTP ${httpPort || socksPort}, DNS ${dnsPort}${bind})`,
      );
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
      applyStreamFromConfig(result.config ?? null);
      applyNetworkFromConfig(result.config ?? null);
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
      applyStreamFromConfig(result.config ?? null);
      applyNetworkFromConfig(result.config ?? null);
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

  async function onSaveStream() {
    setStreamBusy(true);
    setStreamError("");
    setStreamMessage("");
    try {
      const result = await invoke<ConfigResponse>("daemon_apply_config", {
        patch: { stream },
      });
      if (result.config) setCurrentConfig(result.config);
      if (typeof result.path === "string") setConfigPath(result.path);
      applyStreamFromConfig(result.config ?? null);
      const warnings = result.effects?.warnings ?? [];
      const msg = summarizeEffects(result.effects).join(" ");
      setStreamMessage(warnings.length ? `${msg} Warnings: ${warnings.join(" | ")}` : msg || "Saved.");
      log(`stream isolation saved (${JSON.stringify(stream)})`);
      onApplied?.();
    } catch (e) {
      const message = String(e);
      setStreamError(message);
      log(`stream isolation save failed: ${message}`, "error");
    } finally {
      setStreamBusy(false);
    }
  }

  function onStreamToggle(key: keyof StreamSettings, value: boolean) {
    setStream((prev) => ({ ...prev, [key]: value }));
    setStreamDirty(true);
    setStreamError("");
    setStreamMessage("");
  }

  async function onSaveNetwork() {
    const exitCountry = network.exit_country.trim();
    if (exitCountry && !/^[A-Za-z]{2}$/.test(exitCountry)) {
      setNetworkError("Exit country must be an ISO 3166-1 alpha-2 code (two letters), or empty for any country.");
      return;
    }
    setNetworkBusy(true);
    setNetworkError("");
    setNetworkMessage("");
    try {
      const result = await invoke<ConfigResponse>("daemon_apply_config", {
        patch: {
          network: {
            exit_country: exitCountry ? exitCountry.toLowerCase() : null,
            ip_version: network.ip_version,
          },
        },
      });
      if (result.config) setCurrentConfig(result.config);
      if (typeof result.path === "string") setConfigPath(result.path);
      applyNetworkFromConfig(result.config ?? null);
      const warnings = result.effects?.warnings ?? [];
      const msg = summarizeEffects(result.effects).join(" ");
      setNetworkMessage(warnings.length ? `${msg} Warnings: ${warnings.join(" | ")}` : msg || "Saved.");
      log(`network prefs saved (exit_country=${exitCountry || "any"}, ip_version=${network.ip_version})`);
      onApplied?.();
    } catch (e) {
      const message = String(e);
      setNetworkError(message);
      log(`network prefs save failed: ${message}`, "error");
    } finally {
      setNetworkBusy(false);
    }
  }

  function onNetworkExitCountryChange(value: string) {
    setNetwork((prev) => ({ ...prev, exit_country: value }));
    setNetworkDirty(true);
    setNetworkError("");
    setNetworkMessage("");
  }

  function onNetworkIpVersionChange(value: IpVersion) {
    setNetwork((prev) => ({ ...prev, ip_version: value }));
    setNetworkDirty(true);
    setNetworkError("");
    setNetworkMessage("");
  }

  return (
    <section className="card advanced-settings settings-screen" aria-label="Settings">
      <div className="panel-header">
        <div>
          <h2>Settings</h2>
          <p className="muted">Configure tobro. Sensitive controls are power-user gated and never silently ignore unsupported options.</p>
        </div>
        <button type="button" className="logs-toggle" onClick={onClose}>Close</button>
      </div>

      {!powerUser ? (
        <div className="power-user-gate" role="alert">
          <h3>Power-user gate</h3>
          <p>
            Some settings can affect connectivity, expose local services if misconfigured, or require a restart of Tor listeners.
            Only change them if you understand the impact.
          </p>
          <ul className="muted">
            <li>Listener, bind-all, and stream isolation changes can require Stop → Connect.</li>
            <li>Config import/export is validated, but applying the wrong config can break startup/connect behavior.</li>
            <li>Config exports are redacted and contain no secrets; secrets remain in the OS keychain/store.</li>
          </ul>
          <div className="actions">
            <button type="button" className="primary" onClick={enablePowerUser}>I understand, enable settings</button>
            <button type="button" onClick={onClose}>Cancel</button>
          </div>
        </div>
      ) : (
        <div className="settings-shell">
          <div className="settings-tabs" role="tablist" aria-label="Settings tabs" onKeyDown={onTabKeyDown}>
            {SETTINGS_TABS.map((t) => (
              <button
                key={t.id}
                ref={(el) => { tabRefs.current[t.id] = el; }}
                id={`settings-tab-${t.id}`}
                type="button"
                role="tab"
                aria-selected={tab === t.id}
                aria-controls={`settings-panel-${t.id}`}
                tabIndex={tab === t.id ? 0 : -1}
                className={tab === t.id ? "active" : ""}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div
            id="settings-panel-general"
            className="advanced-sections tabpanel"
            role="tabpanel"
            aria-labelledby="settings-tab-general"
            hidden={tab !== "general"}
          >
              <div className="settings-section-head">
                <p className="muted">General settings, proxy listeners, and configuration management.</p>
                <button type="button" className="logs-toggle" onClick={disablePowerUser}>Lock settings</button>
              </div>

              <div className="settings-section">
                <h3>Appearance</h3>
                <div className="field-row">
                  <label htmlFor="settings-theme">Theme</label>
                  <select
                    id="settings-theme"
                    value={theme}
                    onChange={(e) => onThemeChange(e.target.value as ThemePreference)}
                  >
                    <option value="system">System (follow OS)</option>
                    <option value="light">Light</option>
                    <option value="dark">Dark</option>
                  </select>
                </div>
                <p className="muted">Theme applies to app windows (main, Settings, About).</p>
              </div>

              <div className="settings-section">
                <h3>Privacy</h3>
                <label className="checkbox-label" htmlFor="settings-capture-protection">
                  <input
                    id="settings-capture-protection"
                    type="checkbox"
                    checked={captureProtection}
                    onChange={(e) => void onCaptureProtectionChange(e.target.checked)}
                  />
                  <span>
                    <strong>Best-effort window capture protection</strong> (default on)
                  </span>
                </label>
                <p className="muted bind-all-guidance">
                  When enabled, Tobro asks the operating system to hide or exclude app windows from screenshots and screen
                  recordings where supported. This is <strong>best-effort</strong>, not a guarantee: behavior varies by OS
                  version, window manager, display server, remote desktop, capture method, accessibility tooling, and
                  privileged software. It may not prevent all forms of capture (for example some system-level, hardware,
                  or out-of-band recording). Turning it off makes window contents easier to capture.
                </p>
              </div>

              <form className="settings-section port-editor" onSubmit={onSavePorts}>
                <h3>Proxy / listener settings</h3>
                <p className="muted">
                  Configure local SOCKS/HTTP and DNS ports. With the current Arti backend, SOCKS and HTTP share one listener, so HTTP should match SOCKS (use <code>0</code> to follow SOCKS). By default listeners bind to loopback only. Active listener changes require stop/connect.
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
                <div className="bind-all-setting">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={bindAllInterfaces}
                      onChange={(e) => onBindAllChange(e.target.checked)}
                      disabled={portsBusy}
                    />
                    Bind listeners to all interfaces (opt-in, dangerous)
                  </label>
                  {bindAllInterfaces ? (
                    <div className="error bind-all-warning" role="alert">
                      <strong>Security warning / firewall guidance:</strong> {BIND_ALL_WARNING}
                    </div>
                  ) : (
                    <p className="muted bind-all-guidance">
                      Off by default. Enable only if you need other devices on a trusted network to use this Tor proxy, and restrict access with firewall rules.
                    </p>
                  )}
                </div>
                {configPath ? <p className="muted config-hint">Config: <code>{configPath}</code></p> : null}
                {portsError ? <p className="error">{portsError}</p> : null}
                {portsMessage ? <p className="muted">{portsMessage}</p> : null}
                <div className="actions">
                  <button className="primary" type="submit" disabled={portsBusy || !portsDirty}>{portsBusy ? "Saving…" : "Save proxy settings"}</button>
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
                <label className="sr-only" htmlFor="settings-config-import-text">Config JSON patch</label>
                <textarea
                  id="settings-config-import-text"
                  className="config-textarea"
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                  placeholder={'{\n  "proxy": { "socks_port": 9050, "http_port": 9050, "dns_port": 9053, "bind_all_interfaces": false },\n  "network": { "exit_country": "us", "ip_version": "ipv4_preferred" },\n  "stream": { "isolate_destination": false, "isolate_port": false }\n}'}
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

              <div className="settings-section">
                <h3>Help &amp; resources</h3>
                <ul className="help-links muted">
                  {HELP_LINKS.map((l) => (
                    <li key={l.url}>
                      <a href={l.url} onClick={(e) => { e.preventDefault(); void openExternal(l.url); }}>{l.label}</a>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

          <div
            id="settings-panel-node"
            className="advanced-sections tabpanel"
            role="tabpanel"
            aria-labelledby="settings-tab-node"
            hidden={tab !== "node"}
          >
              <div className="settings-section-head">
                <p className="muted">Supported node/stream defaults only. Unsupported C Tor-style restrictions stay hidden and are rejected by validation/import.</p>
              </div>

              <div className="settings-section network-prefs">
                <h3>Exit country / IP version (M2)</h3>
                <p className="muted">
                  Default <code>StreamPrefs</code> applied by tobro’s proxy path when custom network prefs are active (exit country and/or non-default IP version).
                  Exit-country selection uses Arti geoip data and may reduce path diversity or fail to find exits. Changes require Stop/Connect while Tor is running.
                </p>
                <label>
                  Exit country (ISO 3166-1 alpha-2)
                  <input
                    type="text"
                    value={network.exit_country}
                    onChange={(e) => onNetworkExitCountryChange(e.target.value)}
                    placeholder="Any (e.g. us, de, nl)"
                    maxLength={2}
                    spellCheck={false}
                    autoCapitalize="characters"
                    disabled={networkBusy}
                  />
                </label>
                <p className="muted">Leave empty for any exit country. Use a two-letter country code only.</p>
                <label>
                  IP version preference
                  <select
                    value={network.ip_version}
                    onChange={(e) => onNetworkIpVersionChange(e.target.value as IpVersion)}
                    disabled={networkBusy}
                  >
                    <option value="ipv4_preferred">Prefer IPv4, allow IPv6 (default)</option>
                    <option value="ipv6_preferred">Prefer IPv6, allow IPv4</option>
                    <option value="ipv4_only">IPv4 only</option>
                    <option value="ipv6_only">IPv6 only</option>
                  </select>
                </label>
                {networkError ? <p className="error">{networkError}</p> : null}
                {networkMessage ? <p className="muted">{networkMessage}</p> : null}
                <div className="actions">
                  <button className="primary" type="button" disabled={networkBusy || !networkDirty} onClick={() => void onSaveNetwork()}>
                    {networkBusy ? "Saving…" : "Save network prefs"}
                  </button>
                  <button type="button" disabled={networkBusy} onClick={() => void loadConfigState()}>Reset</button>
                </div>
              </div>

              <div className="settings-section node-restrictions">
                <h3>Unsupported restrictions (hidden)</h3>
                <ul className="muted">
                  <li><strong>Entry/exit/exclude/strict node lists:</strong> C Tor-style node restriction lists are not exposed by the pinned Arti APIs used here; these knobs remain hidden and are rejected by config validation/import (never silently ignored).</li>
                  <li><strong>Stream isolation (F-42/F-43):</strong> supported and configurable in Advanced Tor Configuration.</li>
                </ul>
              </div>
            </div>

          <div
            id="settings-panel-advanced"
            className="advanced-sections tabpanel"
            role="tabpanel"
            aria-labelledby="settings-tab-advanced"
            hidden={tab !== "advanced"}
          >
              <div className="settings-section-head">
                <p className="muted">Advanced Tor behavior. Proxy/listener settings are in General.</p>
              </div>

              <div className="settings-section stream-isolation">
                <h3>Stream isolation (F-42/F-43)</h3>
                <p className="muted">
                  Controls how proxy streams are isolated onto Tor circuits. Defaults are off. SOCKS auth isolation is
                  native to Arti when credentials are provided; destination/port isolation is applied by tobro’s isolation
                  front-end when enabled. Changes require Stop/Connect while Tor is running.
                </p>
                <label className="checkbox-label">
                  <input type="checkbox" checked={stream.isolate_destination} disabled={streamBusy}
                    onChange={(e) => onStreamToggle("isolate_destination", e.target.checked)} />
                  <span><strong>Isolate by destination</strong> — streams to different destinations do not share circuits.</span>
                </label>
                <label className="checkbox-label">
                  <input type="checkbox" checked={stream.isolate_port} disabled={streamBusy}
                    onChange={(e) => onStreamToggle("isolate_port", e.target.checked)} />
                  <span><strong>Isolate by port</strong> — streams to different destination ports do not share circuits.</span>
                </label>
                <label className="checkbox-label">
                  <input type="checkbox" checked={stream.isolate_protocol} disabled={streamBusy}
                    onChange={(e) => onStreamToggle("isolate_protocol", e.target.checked)} />
                  <span><strong>Isolate by protocol</strong> — separate isolation by client protocol context (explicit policy; Arti already separates HTTP/SOCKS contexts).</span>
                </label>
                <label className="checkbox-label">
                  <input type="checkbox" checked={stream.keep_alive_isolation} disabled={streamBusy}
                    onChange={(e) => onStreamToggle("keep_alive_isolation", e.target.checked)} />
                  <span><strong>SOCKS auth keep-alive isolation</strong> (F-43) — keep SOCKS username/password isolation explicit for stream lifetime/circuit association.</span>
                </label>
                {streamError ? <p className="error">{streamError}</p> : null}
                {streamMessage ? <p className="muted">{streamMessage}</p> : null}
                <div className="actions">
                  <button className="primary" type="button" disabled={streamBusy || !streamDirty} onClick={() => void onSaveStream()}>
                    {streamBusy ? "Saving…" : "Save stream isolation"}
                  </button>
                  <button type="button" disabled={streamBusy} onClick={() => void loadConfigState()}>Reset</button>
                </div>
              </div>
            </div>
        </div>
      )}
    </section>
  );
}

export const AdvancedSettings = Settings;
