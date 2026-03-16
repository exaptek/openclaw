import { beforeEach, describe, expect, it, vi } from "vitest";

const tailscaleState = vi.hoisted(() => ({
  enableServe: vi.fn(async (_port: number) => {}),
  disableServe: vi.fn(async () => {}),
  enableFunnel: vi.fn(async (_port: number) => {}),
  disableFunnel: vi.fn(async () => {}),
  getHost: vi.fn(async () => "gateway.tailnet.ts.net"),
}));

vi.mock("../infra/tailscale.js", () => ({
  enableTailscaleServe: (port: number) => tailscaleState.enableServe(port),
  disableTailscaleServe: () => tailscaleState.disableServe(),
  enableTailscaleFunnel: (port: number) => tailscaleState.enableFunnel(port),
  disableTailscaleFunnel: () => tailscaleState.disableFunnel(),
  getTailnetHostname: () => tailscaleState.getHost(),
}));

import { startGatewayTailscaleExposure } from "./server-tailscale.js";

function createOwnerStore() {
  let currentToken: string | null = null;
  let nextId = 0;

  return {
    async claim(mode: "serve" | "funnel", port: number) {
      const record = {
        token: `owner-${++nextId}`,
        mode,
        port,
        pid: nextId,
        claimedAt: new Date(0).toISOString(),
      };
      currentToken = record.token;
      return record;
    },
    async isCurrentOwner(token: string) {
      return currentToken === token;
    },
    async clearIfCurrentOwner(token: string) {
      if (currentToken === token) {
        currentToken = null;
      }
    },
  };
}

describe("startGatewayTailscaleExposure", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("skips stale serve cleanup after a newer gateway takes ownership", async () => {
    const ownerStore = createOwnerStore();
    const logTailscale = {
      info: vi.fn(),
      warn: vi.fn(),
    };

    const cleanupA = await startGatewayTailscaleExposure({
      tailscaleMode: "serve",
      resetOnExit: true,
      port: 18789,
      logTailscale,
      ownerStore,
    });
    const cleanupB = await startGatewayTailscaleExposure({
      tailscaleMode: "serve",
      resetOnExit: true,
      port: 18789,
      logTailscale,
      ownerStore,
    });

    await cleanupA?.();
    expect(tailscaleState.disableServe).not.toHaveBeenCalled();
    expect(logTailscale.info).toHaveBeenCalledWith(
      "serve cleanup skipped: newer gateway owns Tailscale exposure",
    );

    await cleanupB?.();
    expect(tailscaleState.disableServe).toHaveBeenCalledTimes(1);
  });

  it("clears ownership after a startup failure", async () => {
    const ownerStore = createOwnerStore();
    const logTailscale = {
      info: vi.fn(),
      warn: vi.fn(),
    };
    tailscaleState.enableServe.mockRejectedValueOnce(new Error("boom"));

    const cleanup = await startGatewayTailscaleExposure({
      tailscaleMode: "serve",
      resetOnExit: true,
      port: 18789,
      logTailscale,
      ownerStore,
    });

    expect(cleanup).not.toBeNull();
    expect(logTailscale.warn).toHaveBeenCalledWith("serve failed: boom");

    await cleanup?.();
    expect(tailscaleState.disableServe).not.toHaveBeenCalled();
  });
});
