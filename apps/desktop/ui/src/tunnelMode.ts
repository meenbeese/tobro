/**
 * Tunnel mode selection: local proxy ports vs full-device VPN.
 *
 * This is a UI-level preference for now: the TUN engine and privileged
 * helper land in M7 (plan §4.7), until then "device" mode is not wired to
 * the daemon and the main page explains that. The selection persists in
 * localStorage and syncs across windows like the theme preference.
 *
 * When the TUN engine ships, flip `DEFAULT_TUNNEL_MODE` to `"device"` to
 * make full-device VPN the default, and wire the mode change into the
 * daemon's `[tun]` config (`tun.enabled`) on connect.
 */

export type TunnelMode = "ports" | "device";

/** Default tunnel mode. `ports` = today's local proxies (SOCKS/HTTP/DNS);
 * `device` = full-device VPN via the privileged TUN helper (M7). Flip this
 * single constant when the TUN engine ships to change the default. */
export const DEFAULT_TUNNEL_MODE: TunnelMode = "ports";

export const TUNNEL_MODE_KEY = "tobro.tunnelMode";
const TUNNEL_MODE_EVENT = "tobro-tunnel-mode-changed";

/** Whether the TUN engine is available in this build. Hard-coded until M7
 * T4/T5 land the platform backends; the daemon rejects `tun.enabled = true`
 * until then. */
export const DEVICE_MODE_AVAILABLE = false;

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
