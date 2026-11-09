import type { ReactNode } from "react";

export type DaemonState =
  | "starting"
  | "bootstrapping"
  | "connected"
  | "serving"
  | "stopping"
  | "stopped"
  | "error";

interface StatusIconProps {
  state?: DaemonState | string | null;
  reachable?: boolean;
  size?: number;
  className?: string;
}

function getColor(state?: string | null, reachable?: boolean): string {
  if (!reachable) return "var(--muted)";
  if (state === "connected" || state === "serving") return "var(--good)";
  if (state === "bootstrapping" || state === "starting") return "var(--warn)";
  if (state === "stopping") return "var(--warn)";
  if (state === "error") return "var(--bad)";
  if (state === "stopped") return "var(--muted)";
  return "var(--muted)";
}

function getTitle(state?: string | null, reachable?: boolean): string {
  if (!reachable) return "Not connected to daemon";
  if (state === "connected" || state === "serving") return "Connected";
  if (state === "bootstrapping") return "Bootstrapping";
  if (state === "starting") return "Starting";
  if (state === "stopping") return "Stopping";
  if (state === "stopped") return "Stopped";
  if (state === "error") return "Error";
  return "Unknown";
}

export function StatusIcon({ state, reachable = false, size = 20, className = "" }: StatusIconProps) {
  const color = getColor(state, reachable);
  const title = getTitle(state, reachable);
  const isActive = reachable && (state === "starting" || state === "bootstrapping");
  const isConnected = reachable && (state === "connected" || state === "serving");

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`status-icon ${className} ${isConnected ? "status-icon-connected" : ""} ${isActive ? "status-icon-active" : ""}`}
      role="img"
      aria-label={title}
      title={title}
    >
      <circle cx="12" cy="12" r="9" stroke={color} strokeWidth="1.5" opacity="0.4" />
      <circle cx="12" cy="12" r="5.5" stroke={color} strokeWidth="2" />
      {isConnected ? (
        <path d="M9.5 12.2L11 13.7L14.5 10.2" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      ) : isActive ? (
        <path
          d="M12 7V12L14.5 13.5"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ) : null}
    </svg>
  );
}

export default StatusIcon;
