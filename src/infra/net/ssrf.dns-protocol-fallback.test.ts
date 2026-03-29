import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { resolve4Mock, resolve6Mock } = vi.hoisted(() => ({
  resolve4Mock: vi.fn<(hostname: string) => Promise<string[]>>(),
  resolve6Mock: vi.fn<(hostname: string) => Promise<string[]>>(),
}));

vi.mock("node:dns/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns/promises")>();
  return {
    ...actual,
    resolve4: (hostname: string) => resolve4Mock(hostname),
    resolve6: (hostname: string) => resolve6Mock(hostname),
  };
});

import type { LookupFn } from "./ssrf.js";

let resolvePinnedHostnameWithPolicy: typeof import("./ssrf.js").resolvePinnedHostnameWithPolicy;

beforeEach(async () => {
  vi.resetModules();
  vi.stubGlobal(
    "fetch",
    vi.fn().mockRejectedValue(new Error("intentionally skip DoH in this test")),
  );
  resolve4Mock.mockReset();
  resolve6Mock.mockReset();
  resolve4Mock.mockResolvedValue(["93.184.216.34"]);
  resolve6Mock.mockResolvedValue([]);
  ({ resolvePinnedHostnameWithPolicy } = await import("./ssrf.js"));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("ssrf DNS protocol fallback", () => {
  it("falls back to resolve4/resolve6 when dns.lookup exhausts EAI_AGAIN retries", async () => {
    vi.useFakeTimers();
    const err = Object.assign(new Error("temporary failure"), { code: "EAI_AGAIN" });
    const lookupImpl = vi.fn().mockRejectedValue(err);
    const lookup = lookupImpl as unknown as LookupFn;

    const pending = resolvePinnedHostnameWithPolicy("example.com", { lookupFn: lookup });

    await vi.runAllTimersAsync();
    const pinned = await pending;

    expect(pinned.addresses).toEqual(["93.184.216.34"]);
    expect(lookupImpl.mock.calls.length).toBeGreaterThanOrEqual(1);
    expect(resolve4Mock).toHaveBeenCalledWith("example.com");
    expect(resolve6Mock).toHaveBeenCalledWith("example.com");
  });
});
