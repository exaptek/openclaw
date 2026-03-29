import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import type { PluginHookSandboxNetworkDeniedEvent } from "../plugins/types.js";
import {
  generateNetworkApprovalId,
  NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX,
  resolveNetworkApprovalWaitDir,
  waitForNetworkApprovalResolution,
  writeNetworkApprovalRequest,
} from "./network-approval-wait.js";
import { matchesSandboxNetworkDenialHint } from "./sandbox-network-denied.js";
import { getToolRuntimeContext } from "./tool-runtime-context.js";

const DEFAULT_APPROVAL_BINARY = "/usr/local/bin/node";

function describeErrorForNetworkWait(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export type NetworkApprovalWaitGateParams<T> = {
  toolName: string;
  error: unknown;
  sandboxed?: boolean;
  signal?: AbortSignal;
  /** HTTP(S) URL used for host:port policy and Telegram context; gate skips when missing or invalid. */
  urlForApproval: string | undefined;
  toolParams: Record<string, unknown>;
  /** Defaults to Node (same heuristic as sandbox_network_denied for web tools). */
  binary?: string;
  retry: () => Promise<T>;
};

/**
 * Shared wait gate for sandboxed web tools: enqueue via `sandbox_network_denied`, poll `resolved.json`, retry once.
 * The NemoClaw `sandbox_network_denied` handler turns that hook into `enqueueNetworkApprovalOutbound`
 * → outbound queue → host relay → **telegram-reply** Lambda (same ARN as `AGENT_OUTPUT_LAMBDA_ARN`).
 * Returns `null` when the gate does not apply (caller should rethrow `error`).
 */
export async function maybeAwaitNetworkApprovalAndRetry<T>(
  params: NetworkApprovalWaitGateParams<T>,
): Promise<T | null> {
  if (!params.sandboxed) {
    return null;
  }
  const waitDir = resolveNetworkApprovalWaitDir();
  if (!waitDir) {
    return null;
  }
  const hookRunner = getGlobalHookRunner();
  if (!hookRunner?.hasHooks("sandbox_network_denied")) {
    return null;
  }
  const denialText = describeErrorForNetworkWait(params.error);
  if (!matchesSandboxNetworkDenialHint(denialText)) {
    return null;
  }
  const rt = getToolRuntimeContext();
  if (!rt?.sessionKey?.trim()) {
    return null;
  }
  const rawUrl = params.urlForApproval?.trim();
  if (!rawUrl) {
    return null;
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return null;
  }
  const host = parsed.hostname;
  const port = parsed.port
    ? Number.parseInt(parsed.port, 10)
    : parsed.protocol === "https:"
      ? 443
      : 80;
  const binary = params.binary?.trim() || DEFAULT_APPROVAL_BINARY;
  const approvalId = generateNetworkApprovalId();
  await writeNetworkApprovalRequest({
    waitDir,
    approvalId,
    body: {
      approvalId,
      url: rawUrl,
      host,
      port,
      binary,
      toolCallId: rt.toolCallId,
      runId: rt.runId,
      sessionKey: rt.sessionKey,
    },
  });
  const event: PluginHookSandboxNetworkDeniedEvent = {
    toolName: params.toolName,
    approvalId,
    denialText,
    toolParams: params.toolParams,
    url: rawUrl,
    host,
    port,
    binary,
    isToolError: true,
  };
  await hookRunner.runSandboxNetworkDenied(event, {
    toolName: params.toolName,
    agentId: rt.agentId,
    sessionKey: rt.sessionKey,
    runId: rt.runId,
    toolCallId: rt.toolCallId,
  });
  const outcome = await waitForNetworkApprovalResolution({
    waitDir,
    approvalId,
    signal: params.signal,
  });
  if (outcome === "timeout") {
    throw new Error(
      `${NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX} Network approval timed out waiting for ${rawUrl}`,
    );
  }
  if (outcome === "aborted") {
    const err = new Error("Aborted");
    err.name = "AbortError";
    throw err;
  }
  if (outcome.action === "deny") {
    throw new Error(
      `${NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX} Network approval denied for ${rawUrl}`,
    );
  }
  return await params.retry();
}
