/**
 * Tunnel mode selection: local proxy ports vs full-device VPN.
 *
 * The selection is kept in localStorage as a UI preference and mirrored into
 * the daemon's `[tun]` config (`tun.enabled`): toggling the mode patches the
 * config when the daemon is reachable, and Connect always sends the selected
 * mode so a freshly started (or previously configured) daemon applies the
 * right mode before Tor connects. Device mode additionally needs the
 * privileged `tobro-helper`, installed from Settings → TUN Mode.
 */

export type TunnelMode = "ports" | "device";

/** Default tunnel mode. `ports` = local proxies (SOCKS/HTTP/DNS);
 * `device` = full-device VPN via the privileged TUN helper. */
export const DEFAULT_TUNNEL_MODE: TunnelMode = "ports";

export const TUNNEL_MODE_KEY = "tobro.tunnelMode";
export const TUNNEL_MODE_EVENT = "tobro-tunnel-mode-changed";

export function readTunnelMode(): TunnelMode {
  try {
    const v = localStorage.getItem(TUNNEL_MODE_KEY);
    if (v === "device") return "device";
    if (v === "ports") return "ports";
  } catch {
    // ignore
  }
  return DEFAULT_TUNNEL_MODE;
}

export function setTunnelMode(mode: TunnelMode) {
  try {
    localStorage.setItem(TUNNEL_MODE_KEY, mode);
  } catch {
    // ignore
  }
  window.dispatchEvent(new CustomEvent(TUNNEL_MODE_EVENT, { detail: mode }));
}
