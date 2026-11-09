import { invoke } from "@tauri-apps/api/core";
import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import {
  readThemePreference,
  setThemePreference,
  type ThemePreference,
} from "./theme";
import {
  readCaptureProtectionEnabled,
  setCaptureProtectionEnabled,
} from "./captureProtection";
import { readGlobalShortcut, applyGlobalShortcut } from "./globalShortcut";

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

type IpVersion =
  "ipv4_preferred" | "ipv6_preferred" | "ipv4_only" | "ipv6_only";

interface NetworkSettings {
  exit_country: string;
  ip_version: IpVersion;
}

type OutboundProxyType =
  "none" | "http" | "https" | "socks4" | "socks5" | "shadowsocks";

interface OutboundProxySettings {
  proxy_type: OutboundProxyType;
  host: string;
  port: string;
  username: string;
  password: string;
  shadowsocks_method: string;
  shadowsocks_password: string;
  sslocal_path: string;
}

const EMPTY_OUTBOUND: OutboundProxySettings = {
  proxy_type: "none",
  host: "",
  port: "1080",
  username: "",
  password: "",
  shadowsocks_method: "aes-256-gcm",
  shadowsocks_password: "",
  sslocal_path: "",
};

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
  if (!trimmed)
    throw new Error("Paste or load a JSON config patch/object first.");
  const parsed = JSON.parse(trimmed) as unknown;
  if (
    parsed &&
    typeof parsed === "object" &&
    !Array.isArray(parsed) &&
    "patch" in (parsed as Record<string, unknown>)
  ) {
    const inner = (parsed as Record<string, unknown>).patch;
    if (inner && typeof inner === "object" && !Array.isArray(inner))
      return inner;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      "Config import must be a JSON object (a config patch or config object).",
    );
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
  if (effects.network_changed)
    lines.push("Network/StreamPrefs defaults changed.");
  if (effects.restart_required) {
    lines.push(
      effects.runtime_active
        ? "Restart required for active runtime: use Stop then Connect after applying."
        : "Changes apply on the next connection/start.",
    );
  } else if (
    !effects.listeners_changed &&
    !effects.stream_changed &&
    !effects.network_changed
  ) {
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

type SettingsTab = "general" | "node" | "onion" | "advanced";
const SETTINGS_TABS: { id: SettingsTab; label: string }[] = [
  { id: "general", label: "General" },
  { id: "node", label: "Node Configuration" },
  { id: "onion", label: "Onion Services" },
  { id: "advanced", label: "Advanced Tor Configuration" },
];

export function Settings({ onClose, onApplied, appendLog }: SettingsProps) {
  const [powerUser, setPowerUser] = useState(readPowerUser);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<SettingsTab>("general");
  const [theme, setTheme] = useState<ThemePreference>(readThemePreference);
  const [captureProtection, setCaptureProtection] = useState(
    readCaptureProtectionEnabled,
  );
  const [globalShortcut, setGlobalShortcut] = useState(readGlobalShortcut);
  const [globalShortcutBusy, setGlobalShortcutBusy] = useState(false);
  const [globalShortcutMessage, setGlobalShortcutMessage] =
    useState<string>("");
  const [globalShortcutError, setGlobalShortcutError] = useState<string>("");
  const [autostart, setAutostart] = useState<{
    enabled: boolean;
    start_minimized: boolean;
  } | null>(null);
  const [autostartInfo, setAutostartInfo] = useState<{
    supported: boolean;
    method: string;
    details: string;
  } | null>(null);
  const [autostartBusy, setAutostartBusy] = useState(false);
  const [autostartMessage, setAutostartMessage] = useState("");
  const [autostartError, setAutostartError] = useState("");
  const [appLock, setAppLock] = useState<{
    enabled: boolean;
    lock_on_idle: boolean;
    idle_minutes: number;
    lock_on_close: boolean;
    prefer_os_auth: boolean;
    has_password: boolean;
    os_auth_available: boolean;
    os_auth_method: string;
  } | null>(null);
  const [appLockBusy, setAppLockBusy] = useState(false);
  const [appLockMessage, setAppLockMessage] = useState("");
  const [appLockError, setAppLockError] = useState("");
  const [lockPassword, setLockPassword] = useState("");
  const [lockPasswordConfirm, setLockPasswordConfirm] = useState("");
  const [lockCurrentPassword, setLockCurrentPassword] = useState("");
  const tabRefs = useRef<Record<SettingsTab, HTMLButtonElement | null>>({
    general: null,
    node: null,
    onion: null,
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

  // Outbound proxy (F-18/F-19)
  const [outbound, setOutbound] =
    useState<OutboundProxySettings>(EMPTY_OUTBOUND);
  const [outboundDirty, setOutboundDirty] = useState(false);
  const [outboundBusy, setOutboundBusy] = useState(false);
  const [outboundMessage, setOutboundMessage] = useState("");
  const [outboundError, setOutboundError] = useState("");
  const [outboundPasswordTouched, setOutboundPasswordTouched] = useState(false);
  const [outboundSsPasswordTouched, setOutboundSsPasswordTouched] =
    useState(false);

  // Config import/export
  const [configPath, setConfigPath] = useState("");
  const [currentConfig, setCurrentConfig] = useState<unknown>(null);
  const [importText, setImportText] = useState("");
  const [configMessages, setConfigMessages] = useState<string[]>([]);
  const [configError, setConfigError] = useState("");
  const fileRef = useRef<HTMLInputElement | null>(null);

  // Bridge/transport test + diagnostics
  const [bridgeTestLine, setBridgeTestLine] = useState("");
  const [bridgeTestBusy, setBridgeTestBusy] = useState(false);
  const [bridgeTestResult, setBridgeTestResult] = useState<unknown>(null);
  const [bridgeTestError, setBridgeTestError] = useState("");

  // Onion services (M5)
  type OnionPortDraft = {
    virt_port: string;
    target_host: string;
    target_port: string;
  };
  type OnionServiceView = {
    id: string;
    nickname: string;
    name: string;
    enabled: boolean;
    onion_address?: string | null;
    key_dir: string;
    ports: Array<{
      virt_port: number;
      target_host: string;
      target_port: number;
    }>;
    runtime_status?: string | null;
    runtime_detail?: string | null;
  };
  const emptyOnionPort = (): OnionPortDraft => ({
    virt_port: "80",
    target_host: "127.0.0.1",
    target_port: "8080",
  });
  const [onionServices, setOnionServices] = useState<OnionServiceView[]>([]);
  const [onionBusy, setOnionBusy] = useState(false);
  const [onionError, setOnionError] = useState("");
  const [onionMessage, setOnionMessage] = useState("");
  const [onionName, setOnionName] = useState("");
  const [onionPorts, setOnionPorts] = useState<OnionPortDraft[]>([
    emptyOnionPort(),
  ]);
  const [onionEditingId, setOnionEditingId] = useState<string | null>(null);

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
    const n = (
      config as {
        network?: Partial<NetworkSettings> & { exit_country?: string | null };
      } | null
    )?.network;
    if (n && typeof n === "object") {
      const ip = n.ip_version;
      const ip_version: IpVersion =
        ip === "ipv6_preferred" || ip === "ipv4_only" || ip === "ipv6_only"
          ? ip
          : "ipv4_preferred";
      setNetwork({
        exit_country: typeof n.exit_country === "string" ? n.exit_country : "",
        ip_version,
      });
      setNetworkDirty(false);
      setNetworkError("");
      setNetworkMessage("");
    }
  }

  function applyOutboundFromConfig(config: unknown) {
    const o = (config as { outbound_proxy?: Record<string, unknown> } | null)
      ?.outbound_proxy;
    if (o && typeof o === "object") {
      const t = o.proxy_type;
      const proxy_type: OutboundProxyType =
        t === "http" ||
        t === "https" ||
        t === "socks4" ||
        t === "socks5" ||
        t === "shadowsocks"
          ? t
          : "none";
      setOutbound({
        proxy_type,
        host: typeof o.host === "string" ? o.host : "",
        port:
          typeof o.port === "number" && Number.isFinite(o.port)
            ? String(o.port)
            : typeof o.port === "string"
              ? o.port
              : "1080",
        username: typeof o.username === "string" ? o.username : "",
        password: typeof o.password === "string" ? o.password : "",
        shadowsocks_method:
          typeof o.shadowsocks_method === "string" && o.shadowsocks_method
            ? o.shadowsocks_method
            : "aes-256-gcm",
        shadowsocks_password:
          typeof o.shadowsocks_password === "string"
            ? o.shadowsocks_password
            : "",
        sslocal_path: typeof o.sslocal_path === "string" ? o.sslocal_path : "",
      });
      setOutboundDirty(false);
      setOutboundPasswordTouched(false);
      setOutboundSsPasswordTouched(false);
      setOutboundError("");
      setOutboundMessage("");
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

  async function loadConfigState(): Promise<unknown | null> {
    try {
      const result = await invoke<ConfigResponse>("daemon_get_config");
      const cfg = result.config ?? null;
      setCurrentConfig(cfg);
      if (typeof result.path === "string") setConfigPath(result.path);
      applyStreamFromConfig(cfg);
      applyNetworkFromConfig(cfg);
      applyOutboundFromConfig(cfg);
      return cfg;
    } catch {
      // best-effort; listener loading may still work from local config
      return null;
    }
  }

  async function loadAutostart() {
    try {
      const s = await invoke<{
        supported: boolean;
        enabled: boolean;
        start_minimized: boolean;
        method: string;
        details: string;
      }>("get_autostart");
      setAutostart({ enabled: s.enabled, start_minimized: s.start_minimized });
      setAutostartInfo({
        supported: s.supported,
        method: s.method,
        details: s.details,
      });
      setAutostartError("");
    } catch (e) {
      setAutostartError(e instanceof Error ? e.message : String(e));
    }
  }

  async function onSaveAutostart(e?: FormEvent) {
    e?.preventDefault();
    if (!autostart) return;
    setAutostartBusy(true);
    setAutostartError("");
    setAutostartMessage("");
    try {
      const s = await invoke<{
        supported: boolean;
        enabled: boolean;
        start_minimized: boolean;
        method: string;
        details: string;
      }>("set_autostart", {
        enabled: autostart.enabled,
        startMinimized: autostart.start_minimized,
      });
      setAutostart({ enabled: s.enabled, start_minimized: s.start_minimized });
      setAutostartInfo({
        supported: s.supported,
        method: s.method,
        details: s.details,
      });
      setAutostartMessage(
        s.enabled
          ? `Autostart enabled (${s.method}).${s.start_minimized ? " Will start minimized." : ""}`
          : "Autostart disabled.",
      );
      log(
        `autostart ${s.enabled ? "enabled" : "disabled"}${s.start_minimized ? " (start minimized)" : ""}`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setAutostartError(msg);
      log(`autostart: ${msg}`, "error");
      await loadAutostart();
    } finally {
      setAutostartBusy(false);
    }
  }

  async function loadAppLock() {
    try {
      const s = await invoke<{
        enabled: boolean;
        lock_on_idle: boolean;
        idle_minutes: number;
        lock_on_close: boolean;
        prefer_os_auth: boolean;
        has_password: boolean;
        os_auth_available: boolean;
        os_auth_method: string;
      }>("get_app_lock_status");
      setAppLock(s);
      setAppLockError("");
    } catch (e) {
      setAppLockError(e instanceof Error ? e.message : String(e));
    }
  }

  async function onSaveAppLockConfig(e?: FormEvent) {
    e?.preventDefault();
    if (!appLock) return;
    setAppLockBusy(true);
    setAppLockError("");
    setAppLockMessage("");
    try {
      const s = await invoke<{
        enabled: boolean;
        lock_on_idle: boolean;
        idle_minutes: number;
        lock_on_close: boolean;
        prefer_os_auth: boolean;
        has_password: boolean;
        os_auth_available: boolean;
        os_auth_method: string;
      }>("set_app_lock_config", {
        enabled: appLock.enabled,
        lockOnIdle: appLock.lock_on_idle,
        idleMinutes: appLock.idle_minutes,
        lockOnClose: appLock.lock_on_close,
        preferOsAuth: appLock.prefer_os_auth,
      });
      setAppLock(s);
      setAppLockMessage(
        s.enabled
          ? "App lock enabled."
          : "App lock settings saved (lock disabled).",
      );
      log(
        `app lock ${s.enabled ? "enabled" : "disabled"} (idle=${s.lock_on_idle}, close=${s.lock_on_close})`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setAppLockError(msg);
      log(`app lock: ${msg}`, "error");
      await loadAppLock();
    } finally {
      setAppLockBusy(false);
    }
  }

  async function onSetAppLockPassword(e?: FormEvent) {
    e?.preventDefault();
    setAppLockBusy(true);
    setAppLockError("");
    setAppLockMessage("");
    if (lockPassword !== lockPasswordConfirm) {
      setAppLockError("New passwords do not match.");
      setAppLockBusy(false);
      return;
    }
    try {
      const s = await invoke<{
        enabled: boolean;
        lock_on_idle: boolean;
        idle_minutes: number;
        lock_on_close: boolean;
        prefer_os_auth: boolean;
        has_password: boolean;
        os_auth_available: boolean;
        os_auth_method: string;
      }>("set_app_lock_password", {
        password: lockPassword,
        currentPassword: appLock?.has_password
          ? lockCurrentPassword || null
          : null,
      });
      setAppLock(s);
      setLockPassword("");
      setLockPasswordConfirm("");
      setLockCurrentPassword("");
      setAppLockMessage("Password saved. Enable app lock when ready.");
      log("app lock password updated");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setAppLockError(msg);
      log(`app lock password: ${msg}`, "error");
    } finally {
      setAppLockBusy(false);
    }
  }

  async function onRemoveAppLockPassword(e?: FormEvent) {
    e?.preventDefault();
    setAppLockBusy(true);
    setAppLockError("");
    setAppLockMessage("");
    try {
      const s = await invoke<{
        enabled: boolean;
        lock_on_idle: boolean;
        idle_minutes: number;
        lock_on_close: boolean;
        prefer_os_auth: boolean;
        has_password: boolean;
        os_auth_available: boolean;
        os_auth_method: string;
      }>("remove_app_lock_password", {
        currentPassword: lockCurrentPassword,
      });
      setAppLock(s);
      setLockPassword("");
      setLockPasswordConfirm("");
      setLockCurrentPassword("");
      setAppLockMessage("Password removed and app lock disabled.");
      log("app lock password removed");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setAppLockError(msg);
      log(`app lock password removal: ${msg}`, "error");
    } finally {
      setAppLockBusy(false);
    }
  }

  useEffect(() => {
    if (powerUser) {
      void loadPorts();
      void loadConfigState();
      void loadAutostart();
      void loadAppLock();
      void loadOnionServices();
    }
  }, [powerUser]);

  useEffect(() => {
    if (powerUser && tab === "onion") {
      void loadOnionServices();
    }
  }, [powerUser, tab]);

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
    log(
      `window capture protection ${enabled ? "enabled (best-effort)" : "disabled"}`,
    );
  }

  async function onSaveGlobalShortcut(e?: FormEvent) {
    e?.preventDefault();
    setGlobalShortcutBusy(true);
    setGlobalShortcutError("");
    setGlobalShortcutMessage("");
    try {
      await applyGlobalShortcut(globalShortcut);
      const v = globalShortcut.trim();
      setGlobalShortcutMessage(
        v
          ? `Global shortcut set to ${v}.`
          : "Global shortcut disabled (default).",
      );
      log(v ? `global shortcut set: ${v}` : "global shortcut disabled");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setGlobalShortcutError(msg);
      log(`global shortcut: ${msg}`, "error");
    } finally {
      setGlobalShortcutBusy(false);
    }
  }

  function onTabKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const order = SETTINGS_TABS.map((t) => t.id);
    const idx = order.indexOf(tab);
    if (idx < 0) return;
    let nextIdx = idx;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % order.length;
    else if (e.key === "ArrowLeft")
      nextIdx = (idx - 1 + order.length) % order.length;
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
        const socksWasFollowing =
          prev.http_port === prev.socks_port || prev.http_port === "0";
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
      setPortsError(
        "Ports must be integers: SOCKS/DNS 1–65535, HTTP 0–65535 (0 follows SOCKS).",
      );
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
      }>("save_proxy_ports", {
        socksPort,
        httpPort,
        dnsPort,
        bindAllInterfaces,
      });
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
      setPortsMessage(
        warnings.length ? `${msg} Warnings: ${warnings.join(" | ")}` : msg,
      );
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

  function onOutboundChange<K extends keyof OutboundProxySettings>(
    key: K,
    value: OutboundProxySettings[K],
  ) {
    setOutbound((prev) => ({ ...prev, [key]: value }));
    setOutboundDirty(true);
    setOutboundError("");
    setOutboundMessage("");
    if (key === "password") setOutboundPasswordTouched(true);
    if (key === "shadowsocks_password") setOutboundSsPasswordTouched(true);
  }

  async function onSaveOutbound(e?: FormEvent) {
    e?.preventDefault();
    setOutboundBusy(true);
    setOutboundError("");
    setOutboundMessage("");
    try {
      const isActive = outbound.proxy_type !== "none";
      const port = isActive ? Number.parseInt(outbound.port, 10) : 0;
      if (isActive && (!Number.isInteger(port) || port < 1 || port > 65535)) {
        throw new Error(
          "Outbound proxy port must be an integer between 1 and 65535.",
        );
      }
      const patchOutbound: Record<string, unknown> = {
        proxy_type: outbound.proxy_type,
        host: outbound.host.trim(),
        port: isActive ? port : 0,
        username: outbound.username,
        shadowsocks_method: outbound.shadowsocks_method.trim() || "aes-256-gcm",
        sslocal_path: outbound.sslocal_path.trim() || null,
      };
      if (!outboundPasswordTouched && outbound.password === "[REDACTED]") {
        // keep existing secret on disk (merge preserves current value)
      } else {
        patchOutbound.password = outbound.password;
      }
      if (
        !outboundSsPasswordTouched &&
        outbound.shadowsocks_password === "[REDACTED]"
      ) {
        // keep existing secret on disk
      } else {
        patchOutbound.shadowsocks_password = outbound.shadowsocks_password;
      }
      const result = await invoke<ConfigResponse>("daemon_apply_config", {
        patch: { outbound_proxy: patchOutbound },
      });
      if (result.config) setCurrentConfig(result.config);
      if (typeof result.path === "string") setConfigPath(result.path);
      applyOutboundFromConfig(result.config ?? null);
      const warnings = result.effects?.warnings ?? [];
      const msg = summarizeEffects(result.effects).join(" ");
      setOutboundMessage(
        warnings.length
          ? `${msg} Warnings: ${warnings.join(" | ")}`
          : msg || "Saved.",
      );
      log(`outbound proxy saved (type=${outbound.proxy_type})`);
      onApplied?.();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setOutboundError(message);
      log(`outbound proxy save failed: ${message}`, "error");
    } finally {
      setOutboundBusy(false);
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
      applyOutboundFromConfig(result.config ?? null);
      setConfigMessages([
        "Loaded current daemon config (redacted; no secrets).",
      ]);
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
      await navigator.clipboard.writeText(
        `${JSON.stringify(currentConfig, null, 2)}\n`,
      );
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
      setConfigMessages([
        `Loaded ${file.name}. Review, then Validate or Apply.`,
      ]);
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
      const result = await invoke<ConfigResponse>("daemon_validate_config", {
        patch,
      });
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
      const result = await invoke<ConfigResponse>("daemon_apply_config", {
        patch,
      });
      if (result.config) setCurrentConfig(result.config);
      if (typeof result.path === "string") setConfigPath(result.path);
      applyStreamFromConfig(result.config ?? null);
      applyNetworkFromConfig(result.config ?? null);
      applyOutboundFromConfig(result.config ?? null);
      const lines = ["Config validated and saved (daemon config API)."];
      lines.push(...summarizeEffects(result.effects));
      lines.push(
        "Redacted config contains no secrets; secrets remain in the OS keychain/store when used.",
      );
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
      setStreamMessage(
        warnings.length
          ? `${msg} Warnings: ${warnings.join(" | ")}`
          : msg || "Saved.",
      );
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
      setNetworkError(
        "Exit country must be an ISO 3166-1 alpha-2 code (two letters), or empty for any country.",
      );
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
      setNetworkMessage(
        warnings.length
          ? `${msg} Warnings: ${warnings.join(" | ")}`
          : msg || "Saved.",
      );
      log(
        `network prefs saved (exit_country=${exitCountry || "any"}, ip_version=${network.ip_version})`,
      );
      onApplied?.();
    } catch (e) {
      const message = String(e);
      setNetworkError(message);
      log(`network prefs save failed: ${message}`, "error");
    } finally {
      setNetworkBusy(false);
    }
  }

  async function onTestBridge(lineOverride?: string) {
    const line = (lineOverride ?? bridgeTestLine).trim();
    if (!line) {
      setBridgeTestError(
        "Paste a bridge line to test (e.g. obfs4, snowflake, webtunnel).",
      );
      return;
    }
    setBridgeTestBusy(true);
    setBridgeTestError("");
    setBridgeTestResult(null);
    log("testing bridge/transport (local validation + PT/config diagnostics)");
    try {
      const result = await invoke<unknown>("daemon_test_bridges", { line });
      setBridgeTestResult(result);
      const r = result as { ok?: boolean; summary?: string };
      log(
        `bridge test: ${r?.ok ? "ok" : "issues found"}${r?.summary ? ` — ${r.summary}` : ""}`,
        r?.ok ? "info" : "error",
      );
    } catch (e) {
      const message = String(e);
      setBridgeTestError(message);
      log(`bridge test failed: ${message}`, "error");
    } finally {
      setBridgeTestBusy(false);
    }
  }

  function validateOnionPorts(ports: OnionPortDraft[]): string | null {
    if (ports.length === 0) return "Add at least one port mapping.";
    const seen = new Set<number>();
    for (let i = 0; i < ports.length; i++) {
      const p = ports[i];
      const virt = Number(p.virt_port);
      const target = Number(p.target_port);
      const host = p.target_host.trim() || "127.0.0.1";
      if (!Number.isInteger(virt) || virt < 1 || virt > 65535) {
        return `Port mapping ${i + 1}: virtual port must be 1–65535.`;
      }
      if (!Number.isInteger(target) || target < 1 || target > 65535) {
        return `Port mapping ${i + 1}: target port must be 1–65535.`;
      }
      if (!host) return `Port mapping ${i + 1}: target host is required.`;
      if (/\s/.test(host))
        return `Port mapping ${i + 1}: target host must not contain whitespace.`;
      if (seen.has(virt))
        return `Port mapping ${i + 1}: duplicate virtual port ${virt}.`;
      seen.add(virt);
    }
    return null;
  }

  function onionPortsToParams(ports: OnionPortDraft[]) {
    return ports.map((p) => ({
      virt_port: Number(p.virt_port),
      target_host: p.target_host.trim() || "127.0.0.1",
      target_port: Number(p.target_port),
    }));
  }

  async function loadOnionServices() {
    setOnionBusy(true);
    setOnionError("");
    try {
      const result = await invoke<{ services?: OnionServiceView[] }>(
        "daemon_onion_list",
      );
      setOnionServices(Array.isArray(result?.services) ? result.services : []);
    } catch (e) {
      setOnionError(String(e));
      log(`onion services: load failed: ${String(e)}`, "error");
    } finally {
      setOnionBusy(false);
    }
  }

  function resetOnionForm() {
    setOnionName("");
    setOnionPorts([emptyOnionPort()]);
    setOnionEditingId(null);
  }

  function startEditOnionService(svc: OnionServiceView) {
    setOnionEditingId(svc.id);
    setOnionName(svc.name);
    setOnionPorts(
      (svc.ports?.length ? svc.ports : []).map((p) => ({
        virt_port: String(p.virt_port),
        target_host: p.target_host || "127.0.0.1",
        target_port: String(p.target_port),
      })),
    );
    if (!svc.ports?.length) setOnionPorts([emptyOnionPort()]);
    setOnionError("");
    setOnionMessage("");
  }

  async function onSaveOnionService(e?: FormEvent) {
    e?.preventDefault();
    const name = onionName.trim();
    if (!name) {
      setOnionError("Service name is required.");
      return;
    }
    const portError = validateOnionPorts(onionPorts);
    if (portError) {
      setOnionError(portError);
      return;
    }
    setOnionBusy(true);
    setOnionError("");
    setOnionMessage("");
    try {
      if (onionEditingId) {
        await invoke("daemon_onion_update", {
          params: {
            id: onionEditingId,
            name,
            ports: onionPortsToParams(onionPorts),
          },
        });
        setOnionMessage(
          "Onion service updated. Reconnect Tor if it is running to apply runtime changes.",
        );
        log(`onion service updated: ${onionEditingId}`);
      } else {
        await invoke("daemon_onion_create", {
          params: {
            name,
            ports: onionPortsToParams(onionPorts),
            enabled: true,
          },
        });
        setOnionMessage(
          "Onion service created (enabled). Connect/start Tor to publish it.",
        );
        log(`onion service created: ${name}`);
      }
      resetOnionForm();
      await loadOnionServices();
    } catch (err) {
      const msg = String(err);
      setOnionError(msg);
      log(`onion service save failed: ${msg}`, "error");
    } finally {
      setOnionBusy(false);
    }
  }

  async function onToggleOnionService(svc: OnionServiceView) {
    setOnionBusy(true);
    setOnionError("");
    setOnionMessage("");
    try {
      await invoke("daemon_onion_update", {
        params: { id: svc.id, enabled: !svc.enabled },
      });
      setOnionMessage(
        svc.enabled
          ? "Onion service disabled."
          : "Onion service enabled. Connect/start Tor to publish it.",
      );
      await loadOnionServices();
    } catch (err) {
      const msg = String(err);
      setOnionError(msg);
      log(`onion service toggle failed: ${msg}`, "error");
    } finally {
      setOnionBusy(false);
    }
  }

  async function onDeleteOnionService(svc: OnionServiceView) {
    if (
      !window.confirm(
        `Delete onion service "${svc.name}"?\n\nThis removes the service and its managed key storage. The .onion identity will be lost unless you have a backup.`,
      )
    ) {
      return;
    }
    setOnionBusy(true);
    setOnionError("");
    setOnionMessage("");
    try {
      await invoke("daemon_onion_delete", { params: { id: svc.id } });
      if (onionEditingId === svc.id) resetOnionForm();
      setOnionMessage("Onion service deleted.");
      log(`onion service deleted: ${svc.id}`);
      await loadOnionServices();
    } catch (err) {
      const msg = String(err);
      setOnionError(msg);
      log(`onion service delete failed: ${msg}`, "error");
    } finally {
      setOnionBusy(false);
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
    <section
      className="card advanced-settings settings-screen"
      aria-label="Settings"
    >
      <div className="panel-header">
        <div>
          <h2>Settings</h2>
        </div>
        <button type="button" className="logs-toggle" onClick={onClose}>
          Close
        </button>
      </div>

      {!powerUser ? (
        <div
          className="power-user-gate"
          role="region"
          aria-labelledby="power-user-gate-title"
        >
          <h3 id="power-user-gate-title">Power-user gate</h3>
          <p>
            Some settings can affect connectivity, expose local services if
            misconfigured, or require a restart of Tor listeners. Only change
            them if you understand the impact.
          </p>
          <ul className="muted">
            <li>
              Listener, bind-all, and stream isolation changes can require Stop
              → Connect.
            </li>
            <li>
              Config import/export is validated, but applying the wrong config
              can break startup/connect behavior.
            </li>
            <li>
              Config exports are redacted and contain no secrets; secrets remain
              in the OS keychain/store.
            </li>
          </ul>
          <div className="actions">
            <button type="button" className="primary" onClick={enablePowerUser}>
              I understand, enable settings
            </button>
            <button type="button" onClick={onClose}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="settings-shell">
          <div
            className="settings-tabs"
            role="tablist"
            aria-label="Settings tabs"
            onKeyDown={onTabKeyDown}
          >
            {SETTINGS_TABS.map((t) => (
              <button
                key={t.id}
                ref={(el) => {
                  tabRefs.current[t.id] = el;
                }}
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
              <p className="muted">
                General settings, proxy listeners, and configuration management.
              </p>
              <button
                type="button"
                className="logs-toggle"
                onClick={disablePowerUser}
              >
                Lock settings
              </button>
            </div>

            <details className="settings-section" open>
              <summary>
                <h3>Appearance</h3>
              </summary>
              <div className="field-row">
                <label htmlFor="settings-theme">Theme</label>
                <select
                  id="settings-theme"
                  value={theme}
                  onChange={(e) =>
                    onThemeChange(e.target.value as ThemePreference)
                  }
                >
                  <option value="system">System (follow OS)</option>
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                </select>
              </div>
              <p className="muted">
                Theme applies to app windows (main, Settings, About).
              </p>
            </details>

            <details className="settings-section" open>
              <summary>
                <h3>Privacy</h3>
              </summary>
              <label
                className="checkbox-label"
                htmlFor="settings-capture-protection"
              >
                <input
                  id="settings-capture-protection"
                  type="checkbox"
                  checked={captureProtection}
                  onChange={(e) =>
                    void onCaptureProtectionChange(e.target.checked)
                  }
                />
                <span>
                  <strong>Best-effort window capture protection</strong>{" "}
                  (default on)
                </span>
              </label>
              <p className="muted bind-all-guidance">
                When enabled, Tobro asks the operating system to hide or exclude
                app windows from screenshots and screen recordings where
                supported. This is <strong>best-effort</strong>, not a
                guarantee: behavior varies by OS version, window manager,
                display server, remote desktop, capture method, accessibility
                tooling, and privileged software. It may not prevent all forms
                of capture (for example some system-level, hardware, or
                out-of-band recording). Turning it off makes window contents
                easier to capture.
              </p>
            </details>

            <form
              className="settings-section"
              onSubmit={(e) => void onSaveGlobalShortcut(e)}
            >
              <details open>
                <summary>
                  <h3>Global shortcut</h3>
                </summary>
                <p className="muted">
                  Configurable system-wide shortcut to{" "}
                  <strong>toggle the Tor connection</strong> (connect/stop).{" "}
                  <strong>Default: off</strong>. Leave empty and save to
                  disable. Example: <code>CommandOrControl+Shift+T</code>{" "}
                  (macOS/Windows/Linux) or <code>Cmd+Shift+T</code> on macOS.
                  Registration can fail if the shortcut is invalid or already
                  used by another app.
                </p>
                <div className="field-row">
                  <label htmlFor="settings-global-shortcut">Shortcut</label>
                  <input
                    id="settings-global-shortcut"
                    type="text"
                    value={globalShortcut}
                    onChange={(e) => {
                      setGlobalShortcut(e.target.value);
                      setGlobalShortcutMessage("");
                      setGlobalShortcutError("");
                    }}
                    placeholder="Disabled (e.g. CommandOrControl+Shift+T)"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </div>
                {globalShortcutError ? (
                  <p className="error">{globalShortcutError}</p>
                ) : null}
                {globalShortcutMessage ? (
                  <p className="muted">{globalShortcutMessage}</p>
                ) : null}
                <div className="actions">
                  <button
                    className="primary"
                    type="submit"
                    disabled={globalShortcutBusy}
                  >
                    {globalShortcutBusy ? "Saving…" : "Save shortcut"}
                  </button>
                  <button
                    type="button"
                    disabled={globalShortcutBusy}
                    onClick={() => {
                      setGlobalShortcut("");
                      setGlobalShortcutMessage("");
                      setGlobalShortcutError("");
                    }}
                  >
                    Clear
                  </button>
                </div>
              </details>
            </form>

            <form
              className="settings-section"
              onSubmit={(e) => void onSaveAutostart(e)}
            >
              <details open>
                <summary>
                  <h3>Startup</h3>
                </summary>
                <p className="muted">
                  Start Tobro automatically when you sign in
                  (platform-specific): <strong>LaunchAgent</strong> on macOS,{" "}
                  <strong>Run key</strong> (HKCU) on Windows,{" "}
                  <strong>systemd user unit</strong> on Linux. Changes apply to
                  the OS autostart configuration.{" "}
                  <strong>Start minimized</strong> launches Tobro hidden to the
                  tray (<code>--minimized</code>).
                </p>
                {!autostartInfo?.supported ? (
                  <p className="muted">
                    Autostart is not available on this platform.
                  </p>
                ) : (
                  <>
                    <label
                      className="checkbox-label"
                      htmlFor="settings-autostart-enabled"
                    >
                      <input
                        id="settings-autostart-enabled"
                        type="checkbox"
                        checked={autostart?.enabled ?? false}
                        disabled={autostartBusy || !autostart}
                        onChange={(e) =>
                          setAutostart((prev) => ({
                            enabled: e.target.checked,
                            start_minimized: prev?.start_minimized ?? false,
                          }))
                        }
                      />
                      <span>
                        <strong>Start at login</strong>
                      </span>
                    </label>
                    <label
                      className="checkbox-label"
                      htmlFor="settings-autostart-minimized"
                    >
                      <input
                        id="settings-autostart-minimized"
                        type="checkbox"
                        checked={autostart?.start_minimized ?? false}
                        disabled={autostartBusy || !autostart?.enabled}
                        onChange={(e) =>
                          setAutostart((prev) => ({
                            enabled: prev?.enabled ?? false,
                            start_minimized: e.target.checked,
                          }))
                        }
                      />
                      <span>
                        <strong>Start minimized</strong> (tray)
                      </span>
                    </label>
                    {autostartInfo ? (
                      <p className="muted">
                        Method: {autostartInfo.method}.{" "}
                        <span className="muted">{autostartInfo.details}</span>
                      </p>
                    ) : null}
                    {autostartError ? (
                      <p className="error">{autostartError}</p>
                    ) : null}
                    {autostartMessage ? (
                      <p className="muted">{autostartMessage}</p>
                    ) : null}
                    <div className="actions">
                      <button
                        className="primary"
                        type="submit"
                        disabled={autostartBusy || !autostart}
                      >
                        {autostartBusy ? "Applying…" : "Apply startup settings"}
                      </button>
                      <button
                        type="button"
                        disabled={autostartBusy}
                        onClick={() => void loadAutostart()}
                      >
                        Reload
                      </button>
                    </div>
                  </>
                )}
              </details>
            </form>

            <details className="settings-section" open>
              <summary>
                <h3>App lock</h3>
              </summary>
              <p className="muted">
                Lock Tobro to prevent casual access to the UI. Unlock with{" "}
                <strong>OS authentication</strong> (when supported/integrated)
                or a <strong>password fallback</strong>. Lock can trigger on{" "}
                <strong>idle</strong> and/or when the window is{" "}
                <strong>closed/hidden to tray</strong> (configurable). Password
                verification is stored locally (PBKDF2-HMAC-SHA256). This
                protects UI access; it does not encrypt Tor state or replace OS
                account security.
              </p>
              {appLock ? (
                <>
                  <form onSubmit={(e) => void onSaveAppLockConfig(e)}>
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={appLock.enabled}
                        disabled={appLockBusy || !appLock.has_password}
                        onChange={(e) =>
                          setAppLock({ ...appLock, enabled: e.target.checked })
                        }
                      />
                      <span>
                        <strong>Enable app lock</strong>
                        {!appLock.has_password ? " (set a password first)" : ""}
                      </span>
                    </label>
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={appLock.lock_on_idle}
                        disabled={appLockBusy}
                        onChange={(e) =>
                          setAppLock({
                            ...appLock,
                            lock_on_idle: e.target.checked,
                          })
                        }
                      />
                      <span>Lock on idle</span>
                    </label>
                    <div className="field-row">
                      <label htmlFor="app-lock-idle-minutes">
                        Idle timeout (minutes)
                      </label>
                      <input
                        id="app-lock-idle-minutes"
                        type="number"
                        min={1}
                        max={240}
                        value={appLock.idle_minutes}
                        disabled={appLockBusy || !appLock.lock_on_idle}
                        onChange={(e) =>
                          setAppLock({
                            ...appLock,
                            idle_minutes: Number(e.target.value) || 5,
                          })
                        }
                      />
                    </div>
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={appLock.lock_on_close}
                        disabled={appLockBusy}
                        onChange={(e) =>
                          setAppLock({
                            ...appLock,
                            lock_on_close: e.target.checked,
                          })
                        }
                      />
                      <span>Lock when window is closed/hidden to tray</span>
                    </label>
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={appLock.prefer_os_auth}
                        disabled={appLockBusy}
                        onChange={(e) =>
                          setAppLock({
                            ...appLock,
                            prefer_os_auth: e.target.checked,
                          })
                        }
                      />
                      <span>Prefer OS authentication when available</span>
                    </label>
                    <p className="muted">
                      OS auth:{" "}
                      {appLock.os_auth_available
                        ? "available"
                        : `not available — ${appLock.os_auth_method}`}
                      . Password fallback is used when OS auth is unavailable.
                    </p>
                    <div className="actions">
                      <button
                        className="primary"
                        type="submit"
                        disabled={appLockBusy}
                      >
                        Save app lock settings
                      </button>
                      <button
                        type="button"
                        disabled={appLockBusy}
                        onClick={() => void loadAppLock()}
                      >
                        Reload
                      </button>
                    </div>
                  </form>

                  <form
                    onSubmit={(e) => void onSetAppLockPassword(e)}
                    style={{ marginTop: 12 }}
                  >
                    <h4>
                      {appLock.has_password
                        ? "Change password"
                        : "Set password"}
                    </h4>
                    {appLock.has_password ? (
                      <div className="field-row">
                        <label htmlFor="app-lock-current">
                          Current password
                        </label>
                        <input
                          id="app-lock-current"
                          type="password"
                          value={lockCurrentPassword}
                          onChange={(e) =>
                            setLockCurrentPassword(e.target.value)
                          }
                          autoComplete="current-password"
                        />
                      </div>
                    ) : null}
                    <div className="field-row">
                      <label htmlFor="app-lock-new">New password</label>
                      <input
                        id="app-lock-new"
                        type="password"
                        value={lockPassword}
                        onChange={(e) => setLockPassword(e.target.value)}
                        autoComplete="new-password"
                      />
                    </div>
                    <div className="field-row">
                      <label htmlFor="app-lock-confirm">
                        Confirm new password
                      </label>
                      <input
                        id="app-lock-confirm"
                        type="password"
                        value={lockPasswordConfirm}
                        onChange={(e) => setLockPasswordConfirm(e.target.value)}
                        autoComplete="new-password"
                      />
                    </div>
                    <div className="actions">
                      <button
                        className="primary"
                        type="submit"
                        disabled={appLockBusy || !lockPassword}
                      >
                        {appLock.has_password
                          ? "Change password"
                          : "Set password"}
                      </button>
                      {appLock.has_password ? (
                        <button
                          type="button"
                          className="danger"
                          disabled={appLockBusy || !lockCurrentPassword}
                          onClick={(e) => void onRemoveAppLockPassword(e)}
                        >
                          Remove password / disable lock
                        </button>
                      ) : null}
                    </div>
                  </form>
                  {appLockError ? (
                    <p className="error">{appLockError}</p>
                  ) : null}
                  {appLockMessage ? (
                    <p className="muted">{appLockMessage}</p>
                  ) : null}
                </>
              ) : (
                <p className="muted">Loading app lock settings…</p>
              )}
            </details>

            <form
              className="settings-section port-editor"
              onSubmit={onSavePorts}
            >
              <details open>
                <summary>
                  <h3>Proxy / listener settings</h3>
                </summary>
                <p className="muted">
                  Configure local SOCKS/HTTP and DNS ports. With the current
                  Arti backend, SOCKS and HTTP share one listener, so HTTP
                  should match SOCKS (use <code>0</code> to follow SOCKS). By
                  default listeners bind to loopback only. Active listener
                  changes require stop/connect.
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
                      <strong>Security warning / firewall guidance:</strong>{" "}
                      {BIND_ALL_WARNING}
                    </div>
                  ) : (
                    <p className="muted bind-all-guidance">
                      Off by default. Enable only if you need other devices on a
                      trusted network to use this Tor proxy, and restrict access
                      with firewall rules.
                    </p>
                  )}
                </div>
                {configPath ? (
                  <p className="muted config-hint">
                    Config: <code>{configPath}</code>
                  </p>
                ) : null}
                {portsError ? <p className="error">{portsError}</p> : null}
                {portsMessage ? <p className="muted">{portsMessage}</p> : null}
                <div className="actions">
                  <button
                    className="primary"
                    type="submit"
                    disabled={portsBusy || !portsDirty}
                  >
                    {portsBusy ? "Saving…" : "Save proxy settings"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void loadPorts()}
                    disabled={portsBusy}
                  >
                    Reload
                  </button>
                </div>
              </details>
            </form>

            <form
              className="settings-section outbound-proxy"
              onSubmit={(e) => void onSaveOutbound(e)}
            >
              <details open>
                <summary>
                  <h3>Outbound proxy (upstream)</h3>
                </summary>
                <p className="muted">
                  Route Tor’s network connections through an upstream proxy.{" "}
                  <strong>HTTP</strong> (CONNECT) and{" "}
                  <strong>SOCKS4/SOCKS5</strong> are applied directly to Arti
                  channels (host must be an IP address with the current
                  backend). <strong>Shadowsocks</strong> starts a local{" "}
                  <code>sslocal</code> sidecar and uses it as a local SOCKS5
                  outbound proxy. Changes require Stop → Connect while Tor is
                  running.
                </p>
                <div className="field-row">
                  <label htmlFor="outbound-proxy-type">Type</label>
                  <select
                    id="outbound-proxy-type"
                    value={outbound.proxy_type}
                    disabled={outboundBusy}
                    onChange={(e) =>
                      onOutboundChange(
                        "proxy_type",
                        e.target.value as OutboundProxyType,
                      )
                    }
                  >
                    <option value="none">None (direct)</option>
                    <option value="http">HTTP CONNECT</option>
                    <option value="https">HTTPS (HTTP CONNECT alias)</option>
                    <option value="socks4">SOCKS4</option>
                    <option value="socks5">SOCKS5</option>
                    <option value="shadowsocks">
                      Shadowsocks (via sslocal)
                    </option>
                  </select>
                </div>
                {outbound.proxy_type !== "none" ? (
                  <>
                    <div className="field-row">
                      <label htmlFor="outbound-proxy-host">
                        {outbound.proxy_type === "shadowsocks"
                          ? "Shadowsocks server host"
                          : "Proxy host (IP address)"}
                      </label>
                      <input
                        id="outbound-proxy-host"
                        type="text"
                        value={outbound.host}
                        disabled={outboundBusy}
                        onChange={(e) =>
                          onOutboundChange("host", e.target.value)
                        }
                        placeholder={
                          outbound.proxy_type === "shadowsocks"
                            ? "ss.example.com or 203.0.113.1"
                            : "127.0.0.1"
                        }
                        autoComplete="off"
                        spellCheck={false}
                      />
                    </div>
                    <div className="field-row">
                      <label htmlFor="outbound-proxy-port">
                        {outbound.proxy_type === "shadowsocks"
                          ? "Shadowsocks server port"
                          : "Proxy port"}
                      </label>
                      <input
                        id="outbound-proxy-port"
                        type="number"
                        min={1}
                        max={65535}
                        inputMode="numeric"
                        value={outbound.port}
                        disabled={outboundBusy}
                        onChange={(e) =>
                          onOutboundChange("port", e.target.value)
                        }
                      />
                    </div>
                    {outbound.proxy_type !== "shadowsocks" ? (
                      <>
                        <div className="field-row">
                          <label htmlFor="outbound-proxy-user">
                            Username (optional)
                          </label>
                          <input
                            id="outbound-proxy-user"
                            type="text"
                            value={outbound.username}
                            disabled={outboundBusy}
                            onChange={(e) =>
                              onOutboundChange("username", e.target.value)
                            }
                            autoComplete="off"
                          />
                        </div>
                        {outbound.proxy_type !== "socks4" ? (
                          <div className="field-row">
                            <label htmlFor="outbound-proxy-pass">
                              Password (optional, sensitive)
                            </label>
                            <input
                              id="outbound-proxy-pass"
                              type="password"
                              value={outbound.password}
                              disabled={outboundBusy}
                              onChange={(e) =>
                                onOutboundChange("password", e.target.value)
                              }
                              autoComplete="new-password"
                            />
                          </div>
                        ) : (
                          <p className="muted">
                            SOCKS4 supports a user ID (username) but not
                            password authentication.
                          </p>
                        )}
                      </>
                    ) : (
                      <>
                        <div className="field-row">
                          <label htmlFor="outbound-ss-method">
                            Shadowsocks method
                          </label>
                          <input
                            id="outbound-ss-method"
                            type="text"
                            value={outbound.shadowsocks_method}
                            disabled={outboundBusy}
                            onChange={(e) =>
                              onOutboundChange(
                                "shadowsocks_method",
                                e.target.value,
                              )
                            }
                            placeholder="aes-256-gcm"
                            autoComplete="off"
                            spellCheck={false}
                          />
                        </div>
                        <div className="field-row">
                          <label htmlFor="outbound-ss-pass">
                            Shadowsocks password (sensitive)
                          </label>
                          <input
                            id="outbound-ss-pass"
                            type="password"
                            value={outbound.shadowsocks_password}
                            disabled={outboundBusy}
                            onChange={(e) =>
                              onOutboundChange(
                                "shadowsocks_password",
                                e.target.value,
                              )
                            }
                            autoComplete="new-password"
                          />
                        </div>
                        <div className="field-row">
                          <label htmlFor="outbound-sslocal-path">
                            sslocal path (optional)
                          </label>
                          <input
                            id="outbound-sslocal-path"
                            type="text"
                            value={outbound.sslocal_path}
                            disabled={outboundBusy}
                            onChange={(e) =>
                              onOutboundChange("sslocal_path", e.target.value)
                            }
                            placeholder="Auto-detect (or /path/to/sslocal)"
                            autoComplete="off"
                            spellCheck={false}
                          />
                        </div>
                        <p className="muted">
                          Requires <code>sslocal</code> from shadowsocks-rust.
                          The sidecar starts on Connect and is stopped on
                          Disconnect.
                        </p>
                      </>
                    )}
                  </>
                ) : null}
                {outboundError ? (
                  <p className="error">{outboundError}</p>
                ) : null}
                {outboundMessage ? (
                  <p className="muted">{outboundMessage}</p>
                ) : null}
                <div className="actions">
                  <button
                    className="primary"
                    type="submit"
                    disabled={outboundBusy || !outboundDirty}
                  >
                    {outboundBusy ? "Saving…" : "Save outbound proxy"}
                  </button>
                  <button
                    type="button"
                    disabled={outboundBusy}
                    onClick={() => void loadConfigState()}
                  >
                    Reload
                  </button>
                </div>
              </details>
            </form>

            <details className="settings-section config-import" open>
              <summary>
                <h3>Config import/export (no secrets)</h3>
              </summary>
              <p className="muted">
                Uses the daemon config API. Exports are{" "}
                <strong>redacted</strong> and contain{" "}
                <strong>no secrets</strong>. Import accepts a JSON object/patch;
                it is merged, validated (<code>deny_unknown_fields</code>), and
                only saved/applied if valid.
              </p>
              <div className="config-actions">
                <button
                  type="button"
                  onClick={() => void onRefreshConfig()}
                  disabled={busy}
                >
                  Load current
                </button>
                <button
                  type="button"
                  onClick={onExport}
                  disabled={busy || !currentConfig}
                >
                  Export JSON
                </button>
                <button
                  type="button"
                  onClick={() => void onCopyCurrent()}
                  disabled={busy || !currentConfig}
                >
                  Copy current
                </button>
              </div>
              <details className="config-preview" open={Boolean(currentConfig)}>
                <summary>Current config (redacted)</summary>
                <pre>
                  {currentConfig
                    ? JSON.stringify(currentConfig, null, 2)
                    : "Load the current config to preview it."}
                </pre>
              </details>
              <div className="config-actions">
                <button
                  type="button"
                  onClick={() => fileRef.current?.click()}
                  disabled={busy}
                >
                  Load file…
                </button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".json,application/json"
                  className="sr-only"
                  onChange={(e) => void onPickFile(e)}
                />
                <button
                  type="button"
                  onClick={() => void onValidate()}
                  disabled={busy || !importText.trim()}
                >
                  Validate
                </button>
                <button
                  type="button"
                  className="primary"
                  onClick={() => void onApplyConfig()}
                  disabled={busy || !importText.trim()}
                >
                  Apply
                </button>
              </div>
              <label className="sr-only" htmlFor="settings-config-import-text">
                Config JSON patch
              </label>
              <textarea
                id="settings-config-import-text"
                className="config-textarea"
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                placeholder={
                  '{\n  "proxy": { "socks_port": 9050, "http_port": 9050, "dns_port": 9053, "bind_all_interfaces": false },\n  "network": { "exit_country": "us", "ip_version": "ipv4_preferred" },\n  "stream": { "isolate_destination": false, "isolate_port": false }\n}'
                }
                spellCheck={false}
                rows={10}
              />
              {configMessages.length ? (
                <ul className="config-messages muted">
                  {configMessages.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              ) : null}
              {configError ? <p className="error">{configError}</p> : null}
            </details>
          </div>

          <div
            id="settings-panel-node"
            className="advanced-sections tabpanel"
            role="tabpanel"
            aria-labelledby="settings-tab-node"
            hidden={tab !== "node"}
          >
            <div className="settings-section-head">
              <p className="muted">
                Supported node/stream defaults only. Unsupported C Tor-style
                restrictions stay hidden and are rejected by validation/import.
              </p>
            </div>

            <details className="settings-section network-prefs" open>
              <summary>
                <h3>Exit country / IP version (M2)</h3>
              </summary>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void onSaveNetwork();
                }}
              >
                <p className="muted">
                  Default <code>StreamPrefs</code> applied by tobro’s proxy path
                  when custom network prefs are active (exit country and/or
                  non-default IP version). Exit-country selection uses Arti
                  geoip data and may reduce path diversity or fail to find
                  exits. Changes require Stop/Connect while Tor is running.
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
                <p className="muted">
                  Leave empty for any exit country. Use a two-letter country
                  code only.
                </p>
                <label>
                  IP version preference
                  <select
                    value={network.ip_version}
                    onChange={(e) =>
                      onNetworkIpVersionChange(e.target.value as IpVersion)
                    }
                    disabled={networkBusy}
                  >
                    <option value="ipv4_preferred">
                      Prefer IPv4, allow IPv6 (default)
                    </option>
                    <option value="ipv6_preferred">
                      Prefer IPv6, allow IPv4
                    </option>
                    <option value="ipv4_only">IPv4 only</option>
                    <option value="ipv6_only">IPv6 only</option>
                  </select>
                </label>
                {networkError ? <p className="error">{networkError}</p> : null}
                {networkMessage ? (
                  <p className="muted">{networkMessage}</p>
                ) : null}
                <div className="actions">
                  <button
                    className="primary"
                    type="submit"
                    disabled={networkBusy || !networkDirty}
                  >
                    {networkBusy ? "Saving…" : "Save network prefs"}
                  </button>
                  <button
                    type="button"
                    disabled={networkBusy}
                    onClick={() => void loadConfigState()}
                  >
                    Reload
                  </button>
                </div>
              </form>
            </details>

            <details className="settings-section bridge-test" open>
              <summary>
                <h3>Transport test &amp; diagnostics</h3>
              </summary>
              <p className="muted">
                Test a bridge/pluggable transport line before connecting. This
                runs <strong>local validation</strong> and{" "}
                <strong>PT/config diagnostics</strong> using the daemon’s
                configured transport paths (it checks format, required
                transports, and whether <code>lyrebird</code>/
                <code>snowflake-client</code>/<code>dnstt-client</code> can be
                resolved). It does not perform a live Tor bootstrap in this
                request and never returns bridge secrets/material in
                diagnostics.
              </p>
              <div className="config-actions">
                <button
                  type="button"
                  disabled={busy || bridgeTestBusy}
                  onClick={async () => {
                    const cfg = (currentConfig ??
                      (await loadConfigState())) as {
                      bridges?: { lines?: unknown[] };
                    } | null;
                    const lines = cfg?.bridges?.lines;
                    if (Array.isArray(lines) && lines.length > 0) {
                      setBridgeTestLine(
                        lines
                          .filter((v): v is string => typeof v === "string")
                          .join("\n"),
                      );
                      setBridgeTestError("");
                    } else {
                      setBridgeTestError(
                        "No bridge lines found in current config.",
                      );
                    }
                  }}
                >
                  Load configured bridges
                </button>
                <button
                  type="button"
                  disabled={
                    bridgeTestBusy || (!bridgeTestResult && !bridgeTestError)
                  }
                  onClick={() => {
                    setBridgeTestResult(null);
                    setBridgeTestError("");
                  }}
                >
                  Clear result
                </button>
              </div>
              <label className="sr-only" htmlFor="settings-bridge-test-line">
                Bridge line to test
              </label>
              <textarea
                id="settings-bridge-test-line"
                className="config-textarea"
                value={bridgeTestLine}
                onChange={(e) => {
                  setBridgeTestLine(e.target.value);
                  setBridgeTestError("");
                }}
                placeholder={
                  "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0\nBridge snowflake 192.0.2.3:80 FINGERPRINT ...\nBridge webtunnel 192.0.2.2:443 FINGERPRINT url=https://example.com/ ver=0.0.1"
                }
                spellCheck={false}
                rows={4}
              />
              <div className="actions">
                <button
                  className="primary"
                  type="button"
                  disabled={bridgeTestBusy || !bridgeTestLine.trim()}
                  onClick={() => void onTestBridge()}
                >
                  {bridgeTestBusy ? "Testing…" : "Test this bridge"}
                </button>
              </div>
              {bridgeTestError ? (
                <p className="error" role="alert">
                  {bridgeTestError}
                </p>
              ) : null}
              {bridgeTestResult ? (
                <div className="bridge-test-result" aria-live="polite">
                  {(() => {
                    const r = bridgeTestResult as {
                      ok?: boolean;
                      summary?: string;
                      transport?: string | null;
                      required_transports?: string[];
                      diagnostics?: string[];
                      valid_count?: number;
                      invalid_count?: number;
                      pt?: Record<
                        string,
                        {
                          required?: boolean;
                          found?: boolean;
                          path?: string;
                          hint?: string;
                        }
                      >;
                    };
                    return (
                      <>
                        <p className={r.ok ? "muted" : "error"}>
                          <strong>{r.ok ? "Pass" : "Issues found"}:</strong>{" "}
                          {r.summary ||
                            (r.ok
                              ? "Diagnostics completed."
                              : "See diagnostics below.")}
                        </p>
                        {r.transport ? (
                          <p className="muted">
                            Detected transport: <code>{r.transport}</code>
                            {r.required_transports?.length
                              ? ` (required: ${r.required_transports.join(", ")})`
                              : ""}
                          </p>
                        ) : null}
                        {typeof r.valid_count === "number" ? (
                          <p className="muted">
                            Validation: {r.valid_count} valid,{" "}
                            {r.invalid_count ?? 0} invalid.
                          </p>
                        ) : null}
                        {r.pt ? (
                          <ul className="muted">
                            {Object.entries(r.pt)
                              .filter(([, v]) => v?.required)
                              .map(([name, v]) => (
                                <li key={name}>
                                  <strong>{name}</strong>:{" "}
                                  {v?.found ? "found" : "missing"}
                                  {v?.path ? (
                                    <>
                                      {" "}
                                      — <code>{v.path}</code>
                                    </>
                                  ) : null}
                                  {v?.hint ? (
                                    <span className="error"> — {v.hint}</span>
                                  ) : null}
                                </li>
                              ))}
                          </ul>
                        ) : null}
                        {Array.isArray(r.diagnostics) &&
                        r.diagnostics.length ? (
                          <ul className={r.ok ? "muted" : "config-messages"}>
                            {r.diagnostics.map((d, i) => (
                              <li key={i}>{d}</li>
                            ))}
                          </ul>
                        ) : null}
                        <details className="config-preview">
                          <summary>Raw diagnostics (JSON)</summary>
                          <pre>{JSON.stringify(bridgeTestResult, null, 2)}</pre>
                        </details>
                      </>
                    );
                  })()}
                </div>
              ) : null}
            </details>

            <details className="settings-section node-restrictions" open>
              <summary>
                <h3>Unsupported restrictions (hidden)</h3>
              </summary>
              <ul className="muted">
                <li>
                  <strong>Bridges/circumvention:</strong> supported here in Node
                  Configuration (Transport test &amp; diagnostics) and via
                  config/CLI (<code>bridges.test</code>, bridge config,
                  Moat/builtin helpers). Bridge lines are sensitive; diagnostics
                  avoid leaking bridge material.
                </li>
                <li>
                  <strong>Entry/exit/exclude/strict node lists:</strong> C
                  Tor-style node restriction lists are not exposed by the pinned
                  Arti APIs used here; these knobs remain hidden and are
                  rejected by config validation/import (never silently ignored).
                </li>
                <li>
                  <strong>Onion services:</strong> configured in the{" "}
                  <strong>Onion Services</strong> tab (CRUD, enable/disable,
                  port mapping validation, key storage management). Runtime
                  launch/publish/status is integrated through the Tor daemon
                  path; enabled services are loaded on connect.
                </li>
                <li>
                  <strong>Stream isolation (F-42/F-43):</strong> supported and
                  configurable in Advanced Tor Configuration.
                </li>
              </ul>
            </details>
          </div>

          <div
            id="settings-panel-onion"
            className="advanced-sections tabpanel"
            role="tabpanel"
            aria-labelledby="settings-tab-onion"
            hidden={tab !== "onion"}
          >
            <div className="settings-section-head">
              <p className="muted">
                Create and manage v3 onion services with local port mappings.
                Runtime publishing uses the Arti-backed Tor path; enabled
                services are loaded when you connect.
              </p>
            </div>
            <details className="settings-section onion-services" open>
              <summary>
                <h3>Onion services</h3>
              </summary>
              <p className="muted">
                Host v3 onion services with local port mappings (
                <code>virtual port → target host:port</code>). Services and
                desired enable/disable state are saved locally; key material is
                stored on disk in the managed onion-services directory (private
                permissions). Runtime publishing requires the Tor runtime
                integration to launch enabled services; status/errors are shown
                when available.
              </p>
              <div className="config-actions">
                <button
                  type="button"
                  disabled={onionBusy}
                  onClick={() => void loadOnionServices()}
                >
                  {onionBusy ? "Loading…" : "Reload services"}
                </button>
              </div>
              {onionError ? (
                <p className="error" role="alert">
                  {onionError}
                </p>
              ) : null}
              {onionMessage ? (
                <p className="muted" aria-live="polite">
                  {onionMessage}
                </p>
              ) : null}

              {onionServices.length ? (
                <ul className="onion-service-list" aria-label="Onion services">
                  {onionServices.map((svc) => (
                    <li key={svc.id} className="onion-service-item">
                      <div className="onion-service-header">
                        <strong>{svc.name}</strong>
                        <span
                          className={`status-badge ${svc.enabled ? "status-badge-serving" : "status-badge-stopped"}`}
                        >
                          {svc.enabled
                            ? svc.runtime_status || "enabled"
                            : "disabled"}
                        </span>
                      </div>
                      {svc.onion_address ? (
                        <p className="muted">
                          <code>{svc.onion_address}</code>
                        </p>
                      ) : (
                        <p className="muted">Address: not published yet</p>
                      )}
                      {svc.runtime_detail ? (
                        <p className="muted">{svc.runtime_detail}</p>
                      ) : null}
                      <p className="muted">
                        Ports:{" "}
                        {(svc.ports || [])
                          .map(
                            (p) =>
                              `${p.virt_port} → ${p.target_host || "127.0.0.1"}:${p.target_port}`,
                          )
                          .join(", ") || "(none)"}
                      </p>
                      <div className="actions">
                        <button
                          type="button"
                          disabled={onionBusy}
                          onClick={() => startEditOnionService(svc)}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          disabled={onionBusy}
                          onClick={() => void onToggleOnionService(svc)}
                        >
                          {svc.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          className="danger"
                          disabled={onionBusy}
                          onClick={() => void onDeleteOnionService(svc)}
                        >
                          Delete
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No onion services configured.</p>
              )}

              <form
                className="onion-service-form"
                onSubmit={(e) => void onSaveOnionService(e)}
              >
                <h4>
                  {onionEditingId
                    ? "Edit onion service"
                    : "Create onion service"}
                </h4>
                <label>
                  Service name
                  <input
                    type="text"
                    value={onionName}
                    onChange={(e) => {
                      setOnionName(e.target.value);
                      setOnionError("");
                    }}
                    placeholder="My service"
                    disabled={onionBusy}
                    required
                  />
                </label>
                <fieldset className="onion-port-mappings">
                  <legend>Port mappings</legend>
                  <p className="muted">
                    Map virtual onion ports to local targets. Validation: ports
                    1–65535, target host required, no duplicate virtual ports.
                  </p>
                  {onionPorts.map((p, idx) => (
                    <div
                      key={idx}
                      className="onion-port-row"
                      aria-label={`Port mapping ${idx + 1}`}
                    >
                      <label>
                        Virtual port
                        <input
                          type="number"
                          min={1}
                          max={65535}
                          value={p.virt_port}
                          onChange={(e) => {
                            const v = e.target.value;
                            setOnionPorts((prev) =>
                              prev.map((row, i) =>
                                i === idx ? { ...row, virt_port: v } : row,
                              ),
                            );
                            setOnionError("");
                          }}
                          disabled={onionBusy}
                          required
                        />
                      </label>
                      <label>
                        Target host
                        <input
                          type="text"
                          value={p.target_host}
                          onChange={(e) => {
                            const v = e.target.value;
                            setOnionPorts((prev) =>
                              prev.map((row, i) =>
                                i === idx ? { ...row, target_host: v } : row,
                              ),
                            );
                            setOnionError("");
                          }}
                          placeholder="127.0.0.1"
                          disabled={onionBusy}
                          required
                        />
                      </label>
                      <label>
                        Target port
                        <input
                          type="number"
                          min={1}
                          max={65535}
                          value={p.target_port}
                          onChange={(e) => {
                            const v = e.target.value;
                            setOnionPorts((prev) =>
                              prev.map((row, i) =>
                                i === idx ? { ...row, target_port: v } : row,
                              ),
                            );
                            setOnionError("");
                          }}
                          disabled={onionBusy}
                          required
                        />
                      </label>
                      <button
                        type="button"
                        className="danger"
                        disabled={onionBusy || onionPorts.length <= 1}
                        onClick={() =>
                          setOnionPorts((prev) =>
                            prev.filter((_, i) => i !== idx),
                          )
                        }
                        aria-label={`Remove port mapping ${idx + 1}`}
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                  <div className="actions">
                    <button
                      type="button"
                      disabled={onionBusy}
                      onClick={() =>
                        setOnionPorts((prev) => [...prev, emptyOnionPort()])
                      }
                    >
                      Add port mapping
                    </button>
                  </div>
                </fieldset>
                <div className="actions">
                  <button
                    className="primary"
                    type="submit"
                    disabled={onionBusy}
                  >
                    {onionBusy
                      ? "Saving…"
                      : onionEditingId
                        ? "Save changes"
                        : "Create service"}
                  </button>
                  {onionEditingId ? (
                    <button
                      type="button"
                      disabled={onionBusy}
                      onClick={resetOnionForm}
                    >
                      Cancel edit
                    </button>
                  ) : null}
                </div>
              </form>
            </details>
          </div>

          <div
            id="settings-panel-advanced"
            className="advanced-sections tabpanel"
            role="tabpanel"
            aria-labelledby="settings-tab-advanced"
            hidden={tab !== "advanced"}
          >
            <div className="settings-section-head">
              <p className="muted">
                Advanced Tor behavior. Proxy/listener settings are in General.
              </p>
            </div>

            <details className="settings-section stream-isolation" open>
              <summary>
                <h3>Stream isolation (F-42/F-43)</h3>
              </summary>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void onSaveStream();
                }}
              >
                <p className="muted">
                  Controls how proxy streams are isolated onto Tor circuits.
                  Defaults are off. SOCKS auth isolation is native to Arti when
                  credentials are provided; destination/port isolation is
                  applied by tobro’s isolation front-end when enabled. Changes
                  require Stop/Connect while Tor is running.
                </p>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={stream.isolate_destination}
                    disabled={streamBusy}
                    onChange={(e) =>
                      onStreamToggle("isolate_destination", e.target.checked)
                    }
                  />
                  <span>
                    <strong>Isolate by destination</strong> — streams to
                    different destinations do not share circuits.
                  </span>
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={stream.isolate_port}
                    disabled={streamBusy}
                    onChange={(e) =>
                      onStreamToggle("isolate_port", e.target.checked)
                    }
                  />
                  <span>
                    <strong>Isolate by port</strong> — streams to different
                    destination ports do not share circuits.
                  </span>
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={stream.isolate_protocol}
                    disabled={streamBusy}
                    onChange={(e) =>
                      onStreamToggle("isolate_protocol", e.target.checked)
                    }
                  />
                  <span>
                    <strong>Isolate by protocol</strong> — separate isolation by
                    client protocol context (explicit policy; Arti already
                    separates HTTP/SOCKS contexts).
                  </span>
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={stream.keep_alive_isolation}
                    disabled={streamBusy}
                    onChange={(e) =>
                      onStreamToggle("keep_alive_isolation", e.target.checked)
                    }
                  />
                  <span>
                    <strong>SOCKS auth keep-alive isolation</strong> (F-43) —
                    keep SOCKS username/password isolation explicit for stream
                    lifetime/circuit association.
                  </span>
                </label>
                {streamError ? <p className="error">{streamError}</p> : null}
                {streamMessage ? (
                  <p className="muted">{streamMessage}</p>
                ) : null}
                <div className="actions">
                  <button
                    className="primary"
                    type="submit"
                    disabled={streamBusy || !streamDirty}
                  >
                    {streamBusy ? "Saving…" : "Save stream isolation"}
                  </button>
                  <button
                    type="button"
                    disabled={streamBusy}
                    onClick={() => void loadConfigState()}
                  >
                    Reload
                  </button>
                </div>
              </form>
            </details>
          </div>
        </div>
      )}
    </section>
  );
}

export const AdvancedSettings = Settings;
