import { useEffect, useMemo, useState } from "react";
import { CopyButton } from "./CopyButton";

export type DaemonState =
  | "starting"
  | "bootstrapping"
  | "connected"
  | "serving"
  | "stopping"
  | "stopped"
  | "error";

interface BootstrapProgress {
  percent?: number;
  ready?: boolean;
  blocked?: string | null;
  detail?: string;
}

interface DaemonStatus {
  state?: DaemonState | string;
  bootstrap?: BootstrapProgress;
  socks_port?: number;
  http_port?: number;
  dns_port?: number;
  bind_all_interfaces?: boolean;
}

interface ConnectionInfoProps {
  status: DaemonStatus | null;
  reachable: boolean;
  connectedAt?: number | null;
  className?: string;
  showCopyButtons?: boolean;
}

function formatDuration(ms: number): string {
  if (ms < 0) return "0s";
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
}

export function ConnectionInfo({
  status,
  reachable,
  connectedAt = null,
  className = "",
  showCopyButtons = true,
}: ConnectionInfoProps) {
  const [now, setNow] = useState(Date.now());

  const isConnected =
    reachable && (status?.state === "connected" || status?.state === "serving");

  useEffect(() => {
    if (!isConnected || !connectedAt) {
      return;
    }
    const interval = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => clearInterval(interval);
  }, [isConnected, connectedAt]);

  const duration = useMemo(() => {
    if (!isConnected || !connectedAt) return null;
    return formatDuration(now - connectedAt);
  }, [isConnected, connectedAt, now]);

  const socksHost = status?.bind_all_interfaces ? "0.0.0.0" : "127.0.0.1";
  const socksPort = status?.socks_port ?? "—";
  const httpPort = status?.http_port ?? status?.socks_port ?? "—";
  const dnsPort = status?.dns_port ?? "—";

  const socksUrl =
    typeof socksPort === "number"
      ? `socks5h://${socksHost}:${socksPort}`
      : null;
  const httpProxy =
    typeof httpPort === "number" ? `http://${socksHost}:${httpPort}` : null;

  if (!reachable || !status) {
    return null;
  }

  return (
    <div className={`connection-info ${className}`}>
      {isConnected ? (
        <>
          <div className="connection-row">
            <span className="connection-label">Status</span>
            <span className="connection-value connection-value-good">
              Connected via Tor
            </span>
          </div>
          {duration ? (
            <div className="connection-row">
              <span className="connection-label">Connected for</span>
              <span className="connection-value">{duration}</span>
            </div>
          ) : null}
          <div className="connection-section">
            <div className="connection-section-title">Proxy endpoints</div>
            <div className="connection-endpoint">
              <div className="connection-endpoint-info">
                <div className="connection-endpoint-label">SOCKS5</div>
                <code className="connection-endpoint-value">
                  {socksHost}:{socksPort}
                </code>
              </div>
              {showCopyButtons && socksUrl ? (
                <CopyButton text={socksUrl} label="Copy" />
              ) : null}
            </div>
            <div className="connection-endpoint">
              <div className="connection-endpoint-info">
                <div className="connection-endpoint-label">HTTP</div>
                <code className="connection-endpoint-value">
                  {socksHost}:{httpPort}
                </code>
              </div>
              {showCopyButtons && httpProxy ? (
                <CopyButton text={httpProxy} label="Copy" />
              ) : null}
            </div>
            <div className="connection-endpoint">
              <div className="connection-endpoint-info">
                <div className="connection-endpoint-label">DNS</div>
                <code className="connection-endpoint-value">
                  {socksHost}:{dnsPort}
                </code>
              </div>
              {showCopyButtons && typeof dnsPort === "number" ? (
                <CopyButton text={`${socksHost}:${dnsPort}`} label="Copy" />
              ) : null}
            </div>
          </div>
        </>
      ) : (
        <div className="connection-section">
          <div className="connection-section-title">Proxy endpoints</div>
          <div className="connection-endpoint">
            <div className="connection-endpoint-info">
              <div className="connection-endpoint-label">SOCKS5</div>
              <code className="connection-endpoint-value connection-value-muted">
                {socksHost}:{socksPort}
              </code>
            </div>
          </div>
          <div className="connection-endpoint">
            <div className="connection-endpoint-info">
              <div className="connection-endpoint-label">HTTP</div>
              <code className="connection-endpoint-value connection-value-muted">
                {socksHost}:{httpPort}
              </code>
            </div>
          </div>
          <div className="connection-endpoint">
            <div className="connection-endpoint-info">
              <div className="connection-endpoint-label">DNS</div>
              <code className="connection-endpoint-value connection-value-muted">
                {socksHost}:{dnsPort}
              </code>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ConnectionInfo;
