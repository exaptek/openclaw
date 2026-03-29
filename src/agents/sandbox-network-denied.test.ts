import { describe, expect, it } from "vitest";
import { NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX } from "./network-approval-wait.js";
import { buildSandboxNetworkDeniedEvent } from "./sandbox-network-denied.js";

describe("buildSandboxNetworkDeniedEvent", () => {
  it("returns an event for web_fetch failure with network-like error", () => {
    const ev = buildSandboxNetworkDeniedEvent({
      toolName: "web_fetch",
      toolParams: { url: "https://example.com/path" },
      isToolError: true,
      sanitizedResult: { details: { status: "failed" }, error: "fetch failed ETIMEDOUT" },
      errorMessage: "failed",
    });
    expect(ev).not.toBeNull();
    expect(ev?.toolName).toBe("web_fetch");
    expect(ev?.host).toBe("example.com");
    expect(ev?.port).toBe(443);
    expect(ev?.denialText.toLowerCase()).toContain("fetch failed");
  });

  it("returns null when tool is not a network tool", () => {
    expect(
      buildSandboxNetworkDeniedEvent({
        toolName: "cron",
        toolParams: {},
        isToolError: true,
        sanitizedResult: { error: "fetch failed" },
        errorMessage: "fetch failed",
      }),
    ).toBeNull();
  });

  it("returns null when error text does not look like network egress", () => {
    expect(
      buildSandboxNetworkDeniedEvent({
        toolName: "web_fetch",
        toolParams: { url: "https://a.com" },
        isToolError: true,
        sanitizedResult: { message: "validation error" },
        errorMessage: "validation error",
      }),
    ).toBeNull();
  });

  it("returns null on success", () => {
    expect(
      buildSandboxNetworkDeniedEvent({
        toolName: "web_fetch",
        toolParams: { url: "https://a.com" },
        isToolError: false,
        sanitizedResult: { ok: true },
      }),
    ).toBeNull();
  });

  it("returns null after network approval wait gate (suppress duplicate Telegram)", () => {
    expect(
      buildSandboxNetworkDeniedEvent({
        toolName: "web_fetch",
        toolParams: { url: "https://a.com" },
        isToolError: true,
        sanitizedResult: {
          error: `${NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX} denied`,
        },
        errorMessage: `${NETWORK_APPROVAL_WAIT_SUPPRESS_PREFIX} denied`,
      }),
    ).toBeNull();
  });
});
