/**
 * Defense-in-depth log redaction for the UI (copy/save/display).
 * The daemon is the primary redaction boundary; this catches accidental leaks.
 */
export const REDACTED = "[REDACTED]";

function redactLabeledSecrets(input: string): string {
  const labels = [
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "access_token",
    "access-token",
    "private_key",
    "private-key",
    "credential",
    "credentials",
    "x25519",
    "ed25519",
    "client_auth",
    "client-auth",
    "auth_private",
    "cert",
    "fingerprint",
  ];
  let out = input;
  for (const label of labels) {
    const re = new RegExp(
      `(^|[^A-Za-z0-9_-])(${label.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")})([\\s:=\\"']+)([^\\s&;,\\"'\\r\\n]+)`,
      "gi",
    );
    out = out.replace(re, (_m, pre, lab, sep) => `${pre}${lab}${sep}${REDACTED}`);
  }
  return out;
}

function redactUrlCredentials(input: string): string {
  return input.replace(
    /\b((?:https?|socks[45]):\/\/)([^/\s@]+)@/gi,
    `$1${REDACTED}@`,
  );
}

function redactPrivateKeyBlocks(input: string): string {
  let out = input.replace(
    /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g,
    "[REDACTED PRIVATE KEY]",
  );
  out = out.replace(
    /(:descriptor:x25519:)[A-Za-z0-9+/=._-]+/g,
    `$1${REDACTED}`,
  );
  return out;
}

function redactBridgeLikeLines(input: string): string {
  return input
    .split("\n")
    .map((line) => {
      const trimmed = line.trimStart().toLowerCase();
      if (
        trimmed.startsWith("bridge ") ||
        trimmed.startsWith("obfs4 ") ||
        trimmed.startsWith("snowflake ") ||
        trimmed.startsWith("webtunnel ") ||
        trimmed.startsWith("meek_lite ") ||
        trimmed.startsWith("meek ") ||
        trimmed.startsWith("conjure ") ||
        trimmed.startsWith("dnstt ")
      ) {
        const prefix = line.trimStart().split(/\s+/)[0] ?? "Bridge";
        return `${prefix} ${REDACTED}`;
      }
      return line;
    })
    .join("\n");
}

export function redactLogText(input: string): string {
  let out = input;
  out = redactLabeledSecrets(out);
  out = redactUrlCredentials(out);
  out = redactPrivateKeyBlocks(out);
  out = redactBridgeLikeLines(out);
  return out;
}
