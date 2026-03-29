/**
 * Detect sandbox / network egress failures for web tools so the gateway can emit
 * the `sandbox_network_denied` plugin hook (OpenShell policy, proxy 403, timeouts, etc.).
 */

import type { PluginHookSandboxNetworkDeniedEvent } from "../plugins/types.js";
import { NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX } from "./network-approval-wait.js";

const DEFAULT_NETWORK_TOOLS = new Set(["web_fetch", "browser"]);

/** Broad match for fetch / proxy / DNS / TLS failures (aligned with operator log tailers). */
const DENIAL_HINT =
  /den(y|ied|ial)|block(ed)?|forbidden|not allowed|egress|policy|403|econnrefused|etimedout|fetch failed|enetunreach|url-fetch|ssl|tls|network|getaddrinfo|eai_again|enotfound|connection refused|certificate/i;

/** True when `text` matches the same egress / policy / DNS / TLS heuristics as `sandbox_network_denied`. */
export function matchesSandboxNetworkDenialHint(text: string): boolean {
  const t = text.trim();
  if (!t) {
    return false;
  }
  return DENIAL_HINT.test(t);
}

function readUrlFromToolParams(
  toolName: string,
  toolParams: Record<string, unknown>,
): string | undefined {
  const top = toolParams["url"];
  if (typeof top === "string" && top.trim()) {
    return top.trim();
  }
  if (toolName === "browser") {
    const req = toolParams["request"];
    if (req && typeof req === "object") {
      const u = (req as Record<string, unknown>)["url"];
      if (typeof u === "string" && u.trim()) {
        return u.trim();
      }
    }
  }
  return undefined;
}

function inferBinary(toolName: string): string {
  if (toolName === "browser") {
    return "/usr/local/bin/node";
  }
  return "/usr/local/bin/node";
}

/**
 * When a web tool failed and the result looks like a network / policy denial,
 * build the event for `sandbox_network_denied`. Otherwise return null.
 */
export function buildSandboxNetworkDeniedEvent(params: {
  toolName: string;
  toolParams: Record<string, unknown>;
  isToolError: boolean;
  sanitizedResult: unknown;
  errorMessage?: string;
}): PluginHookSandboxNetworkDeniedEvent | null {
  if (!params.isToolError) {
    return null;
  }
  if (!DEFAULT_NETWORK_TOOLS.has(params.toolName)) {
    return null;
  }

  const parts: string[] = [];
  if (params.errorMessage) {
    parts.push(params.errorMessage);
  }
  const sr = params.sanitizedResult;
  parts.push(typeof sr === "string" ? sr : JSON.stringify(sr ?? null));
  const denialText = parts.join("\n").trim();
  if (denialText.includes(NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX)) {
    return null;
  }
  if (!denialText || !DENIAL_HINT.test(denialText)) {
    return null;
  }

  const url = readUrlFromToolParams(params.toolName, params.toolParams);
  let host: string | undefined;
  let port: number | undefined;
  if (url) {
    try {
      const u = new URL(url);
      host = u.hostname;
      const p = u.port;
      port = p ? Number.parseInt(p, 10) : u.protocol === "https:" ? 443 : 80;
    } catch {
      // ignore invalid URL
    }
  }

  return {
    toolName: params.toolName,
    denialText,
    toolParams: params.toolParams,
    url,
    host,
    port,
    binary: inferBinary(params.toolName),
    isToolError: true,
  };
}
