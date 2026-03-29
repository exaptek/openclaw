import type { AgentTool } from "@mariozechner/pi-agent-core";
import {
  toToolDefinitions,
  type ToolDefinitionAdapterOptions,
} from "../pi-tool-definition-adapter.js";
import type { ToolRuntimeContext } from "../tool-runtime-context.js";

// We always pass tools via `customTools` so our policy filtering, sandbox integration,
// and extended toolset remain consistent across providers.
type AnyAgentTool = AgentTool;

export function splitSdkTools(options: {
  tools: AnyAgentTool[];
  sandboxEnabled: boolean;
  toolRuntime?: Omit<ToolRuntimeContext, "toolCallId">;
}): {
  builtInTools: AnyAgentTool[];
  customTools: ReturnType<typeof toToolDefinitions>;
} {
  const { tools, toolRuntime } = options;
  const adapterOptions: ToolDefinitionAdapterOptions | undefined = toolRuntime
    ? { toolRuntime }
    : undefined;
  return {
    builtInTools: [],
    customTools: toToolDefinitions(tools, adapterOptions),
  };
}
