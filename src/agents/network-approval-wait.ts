import { randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

/** Prefix for errors that must not re-trigger `sandbox_network_denied` after a wait gate. */
export const NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX = "network_approval_wait_suppress:";

export type NetworkApprovalResolved = {
  action: "approve" | "deny";
};

function parseTimeoutMs(): number {
  const raw = process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_TIMEOUT_MS?.trim();
  if (!raw) {
    return 15 * 60 * 1000;
  }
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 15 * 60 * 1000;
}

function parsePollMs(): number {
  const raw = process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_POLL_MS?.trim();
  if (!raw) {
    return 1000;
  }
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 200 ? n : 1000;
}

export function resolveNetworkApprovalWaitDir(): string | undefined {
  const d = process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_DIR?.trim();
  return d || undefined;
}

export function generateNetworkApprovalId(): string {
  return randomBytes(4).toString("hex");
}

export async function writeNetworkApprovalRequest(params: {
  waitDir: string;
  approvalId: string;
  body: Record<string, unknown>;
}): Promise<string> {
  const dir = path.join(params.waitDir, params.approvalId);
  await fs.mkdir(dir, { recursive: true });
  const p = path.join(dir, "request.json");
  await fs.writeFile(p, `${JSON.stringify(params.body, null, 2)}\n`, "utf8");
  return dir;
}

export async function readResolvedFile(
  waitDir: string,
  approvalId: string,
): Promise<NetworkApprovalResolved | null> {
  const p = path.join(waitDir, approvalId, "resolved.json");
  try {
    const raw = await fs.readFile(p, "utf8");
    const data = JSON.parse(raw) as { action?: string };
    const a = typeof data.action === "string" ? data.action.toLowerCase() : "";
    if (a === "approve" || a === "deny") {
      return { action: a };
    }
  } catch {
    // missing or invalid
  }
  return null;
}

/**
 * Poll until `resolved.json` appears, the abort signal fires, or timeout.
 */
export async function waitForNetworkApprovalResolution(params: {
  waitDir: string;
  approvalId: string;
  signal?: AbortSignal;
}): Promise<NetworkApprovalResolved | "timeout" | "aborted"> {
  const deadline = Date.now() + parseTimeoutMs();
  const pollMs = parsePollMs();
  while (Date.now() < deadline) {
    if (params.signal?.aborted) {
      return "aborted";
    }
    const resolved = await readResolvedFile(params.waitDir, params.approvalId);
    if (resolved) {
      return resolved;
    }
    try {
      await sleep(pollMs, params.signal);
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        return "aborted";
      }
      throw err;
    }
  }
  return "timeout";
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      const err = new Error("Aborted");
      err.name = "AbortError";
      reject(err);
      return;
    }
    const t = setTimeout(resolve, ms);
    const onAbort = () => {
      clearTimeout(t);
      const err = new Error("Aborted");
      err.name = "AbortError";
      reject(err);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
