import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Per tool-call context for embedded runs (session/run identity for hooks and wait gates).
 */
export type ToolRuntimeContext = {
  sessionKey?: string;
  runId?: string;
  agentId?: string;
  toolCallId?: string;
};

export const toolRuntimeContext = new AsyncLocalStorage<ToolRuntimeContext>();

export function getToolRuntimeContext(): ToolRuntimeContext | undefined {
  return toolRuntimeContext.getStore();
}
