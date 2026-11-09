import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";

export interface AboutProps {
  onClose: () => void;
}

const HELP_LINKS = [
  { label: "Tor Project", url: "https://www.torproject.org/", note: "Tor network and documentation" },
  { label: "Arti (Tor in Rust)", url: "https://gitlab.torproject.org/tpo/core/arti", note: "Embedded Tor implementation used by Tobro" },
  { label: "Tauri", url: "https://tauri.app/", note: "Desktop app framework" },
];

async function openExternal(url: string) {
  try {
    await invoke("open_external_url", { url });
  } catch {
    // fallback: no-op in restricted contexts
  }
}

interface DaemonStatus {
  state?: string;
  socks_port?: number;
  http_port?: number;
  dns_port?: number;
  bind_all_interfaces?: boolean;
}

interface DependencyInfo {
  name: string;
  version: string;
  note?: string;
}

const DEPENDENCIES: DependencyInfo[] = [
  { name: "Arti", version: "2.8.0", note: "Tor implementation (embedded client)" },
  { name: "arti-client", version: "0.48.0", note: "Tor client library (geoip enabled for exit country)" },
  { name: "tor-rtcompat", version: "0.48.0", note: "Tokio/native-tls runtime compat" },
  { name: "Tokio", version: "1.54", note: "Async runtime" },
  { name: "Tauri", version: "2.x", note: "Desktop shell" },
  { name: "React", version: "19.x", note: "UI framework" },
  { name: "TypeScript", version: "5.6.x", note: "UI type checking" },
  { name: "Vite", version: "8.x", note: "UI build tooling" },
  { name: "serde / serde_json", version: "1.x", note: "Serialization and IPC payloads" },
  { name: "clap", version: "4.x", note: "CLI parsing (tobrod/tobroctl)" },
  { name: "libsql", version: "0.6.x", note: "Embedded local storage (tobro-store)" },
];

export function About({ onClose }: AboutProps) {
  const [runtime, setRuntime] = useState<string>("Checking daemon runtime…");
  const [status, setStatus] = useState<string>("");

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await invoke<DaemonStatus>("status");
        if (cancelled) return;
        const bind = s?.bind_all_interfaces ? "0.0.0.0" : "127.0.0.1";
        const ports =
          typeof s?.socks_port === "number"
            ? `SOCKS ${bind}:${s.socks_port}, HTTP ${bind}:${s.http_port ?? s.socks_port}, DNS ${bind}:${s.dns_port ?? "—"}`
            : "ports unavailable";
        setStatus(`State: ${s?.state ?? "unknown"} · ${ports}`);
      } catch (e) {
        if (!cancelled) setStatus(`Daemon status unavailable: ${String(e)}`);
      }
      try {
        // Best-effort: some builds expose daemon hello/status details via status/events;
        // show what we can from status command context without requiring a new API.
        const s = await invoke<Record<string, unknown>>("status");
        if (cancelled) return;
        const dv = typeof s?.daemon_version === "string" ? s.daemon_version : null;
        const av = typeof s?.arti_version === "string" ? s.arti_version : null;
        if (dv || av) {
          setRuntime(`daemon ${dv ?? "?"} · Arti ${av ?? "?"}`);
        } else {
          setRuntime("Runtime version details are shown in the main window when the daemon reports hello/status.");
        }
      } catch {
        if (!cancelled) setRuntime("Daemon not reachable (runtime details unavailable).");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="card about-screen settings-screen" aria-label="About Tobro">
      <div className="panel-header">
        <div>
          <h2>About Tobro</h2>
          <p className="muted">Desktop Tor client powered by embedded Arti, with a Tauri + React shell.</p>
        </div>
        <button type="button" className="logs-toggle" onClick={onClose}>Close</button>
      </div>

      <div className="advanced-sections">
        <div className="settings-section">
          <h3>Application</h3>
          <ul className="muted">
            <li><strong>Product:</strong> Tobro</li>
            <li><strong>Version:</strong> 0.0.0 (development)</li>
            <li><strong>License:</strong> GPL-3.0-only</li>
            <li><strong>Rust toolchain (workspace):</strong> 1.92 (MSRV target per workspace config)</li>
            <li><strong>Platforms:</strong> macOS, Windows, Linux (desktop)</li>
          </ul>
          <p className="muted">
            Tobro embeds Arti for Tor client functionality and uses a local daemon (<code>tobrod</code>) plus
            desktop UI. It aims for honest status reporting and does not silently ignore unsupported configuration knobs.
          </p>
        </div>

        <div className="settings-section">
          <h3>Runtime (best effort)</h3>
          <p className="muted">{runtime}</p>
          {status ? <p className="muted">{status}</p> : null}
        </div>

        <div className="settings-section">
          <h3>Help &amp; resources</h3>
          <ul className="help-links muted">
            {HELP_LINKS.map((l) => (
              <li key={l.url}>
                <a href={l.url} onClick={(e) => { e.preventDefault(); void openExternal(l.url); }}>{l.label}</a>
                {l.note ? <span> — {l.note}</span> : null}
              </li>
            ))}
          </ul>
        </div>

        <div className="settings-section">
          <h3>Key dependencies</h3>
          <p className="muted">Pinned/declared versions from workspace and UI manifests (build may resolve compatible patch versions where applicable).</p>
          <div className="config-preview" style={{ maxHeight: "none" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: "6px 8px", borderBottom: "1px solid var(--border)" }}>Dependency</th>
                  <th style={{ textAlign: "left", padding: "6px 8px", borderBottom: "1px solid var(--border)" }}>Version</th>
                  <th style={{ textAlign: "left", padding: "6px 8px", borderBottom: "1px solid var(--border)" }}>Notes</th>
                </tr>
              </thead>
              <tbody>
                {DEPENDENCIES.map((d) => (
                  <tr key={d.name}>
                    <td style={{ padding: "6px 8px", borderBottom: "1px solid var(--border)", verticalAlign: "top" }}><code>{d.name}</code></td>
                    <td style={{ padding: "6px 8px", borderBottom: "1px solid var(--border)", verticalAlign: "top" }}>{d.version}</td>
                    <td style={{ padding: "6px 8px", borderBottom: "1px solid var(--border)", verticalAlign: "top", color: "var(--muted)" }}>{d.note ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="settings-section">
          <h3>Notices</h3>
          <p className="muted">
            Tor is a trademark of The Tor Project. Arti is developed by The Tor Project. This application is not
            affiliated with or endorsed by The Tor Project. Use Tor responsibly and review security/privacy guidance
            appropriate to your threat model.
          </p>
        </div>
      </div>
    </section>
  );
}
