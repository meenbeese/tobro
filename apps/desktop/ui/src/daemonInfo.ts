const DAEMON_INFO_KEY = "tobro.daemon-info";

/**
 * Human-readable daemon runtime string set by the main window when the
 * daemon reports hello, e.g. "daemon 0.1.0 (rpc v1, macos, arti 2.8)".
 * Shared through localStorage so other windows (About, Logs) can read it.
 */
export function storeDaemonInfo(info: string) {
  try {
    localStorage.setItem(DAEMON_INFO_KEY, info);
  } catch {
    // ignore
  }
}

export function readDaemonInfo(): string | null {
  try {
    return localStorage.getItem(DAEMON_INFO_KEY);
  } catch {
    // ignore
  }
  return null;
}
