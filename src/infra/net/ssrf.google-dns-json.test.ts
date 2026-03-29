import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { resolve4Mock, resolve6Mock, fetchMock } = vi.hoisted(() => ({
  resolve4Mock: vi.fn(),
  resolve6Mock: vi.fn(),
  fetchMock: vi.fn(),
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
  vi.stubGlobal("fetch", fetchMock);
  resolve4Mock.mockReset();
  resolve6Mock.mockReset();
  fetchMock.mockReset();
  const etimeout = Object.assign(new Error("timeout"), { code: "ETIMEOUT" });
  resolve4Mock.mockRejectedValue(etimeout);
  resolve6Mock.mockRejectedValue(etimeout);
  fetchMock.mockImplementation(async (input: string | URL) => {
    const u = String(input);
    if (u.includes("type=A")) {
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer: [{ type: 1, data: "93.184.216.34" }],
        }),
        { status: 200 },
      );
    }
    if (u.includes("type=AAAA")) {
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  });
  ({ resolvePinnedHostnameWithPolicy } = await import("./ssrf.js"));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("ssrf Google DNS JSON fallback", () => {
  it("calls dns.google JSON before dns.lookup when HTTP_PROXY is set", async () => {
    vi.stubEnv("HTTP_PROXY", "http://127.0.0.1:9");
    vi.resetModules();
    vi.stubGlobal("fetch", fetchMock);
    resolve4Mock.mockReset();
    resolve6Mock.mockReset();
    fetchMock.mockReset();
    const etimeout = Object.assign(new Error("timeout"), { code: "ETIMEOUT" });
    resolve4Mock.mockRejectedValue(etimeout);
    resolve6Mock.mockRejectedValue(etimeout);
    fetchMock.mockImplementation(async (input: string | URL) => {
      const u = String(input);
      if (u.includes("type=A")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ type: 1, data: "93.184.216.34" }],
          }),
          { status: 200 },
        );
      }
      if (u.includes("type=AAAA")) {
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    const { resolvePinnedHostnameWithPolicy: resolveWithProxy } = await import("./ssrf.js");
    const err = Object.assign(new Error("should not call lookup"), { code: "EAI_AGAIN" });
    const lookupImpl = vi.fn().mockRejectedValue(err);
    const lookup = lookupImpl as unknown as LookupFn;

    const pinned = await resolveWithProxy("example.com", { lookupFn: lookup });

    expect(pinned.addresses).toEqual(["93.184.216.34"]);
    expect(lookupImpl).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalled();
  });

  it("uses dns.google JSON when lookup and resolve4/6 fail", async () => {
    vi.useFakeTimers();
    const err = Object.assign(new Error("temporary failure"), { code: "EAI_AGAIN" });
    const lookupImpl = vi.fn().mockRejectedValue(err);
    const lookup = lookupImpl as unknown as LookupFn;

    const pending = resolvePinnedHostnameWithPolicy("example.com", { lookupFn: lookup });
    await vi.runAllTimersAsync();
    const pinned = await pending;

    expect(pinned.addresses).toEqual(["93.184.216.34"]);
    expect(fetchMock).toHaveBeenCalled();
    const urls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(urls.some((u) => u.includes("dns.google/resolve") && u.includes("type=A"))).toBe(true);
  });

  it("surfaces DoH and protocol errors when both fallbacks fail after EAI_AGAIN", async () => {
    const err = Object.assign(new Error("temporary failure"), { code: "EAI_AGAIN" });
    const lookupImpl = vi.fn().mockRejectedValue(err);
    const lookup = lookupImpl as unknown as LookupFn;

    fetchMock.mockRejectedValue(new Error("Google DNS JSON HTTP 403"));
    const etimeout = Object.assign(new Error("timeout"), { code: "ETIMEOUT" });
    resolve4Mock.mockRejectedValue(etimeout);
    resolve6Mock.mockRejectedValue(etimeout);

    try {
      await resolvePinnedHostnameWithPolicy("bad.example", { lookupFn: lookup });
      expect.fail("expected rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(Error);
      expect((e as Error).message).toMatch(/DNS resolution failed for bad\.example/);
      expect((e as Error).message).toMatch(/DNS-over-HTTPS: Google DNS JSON HTTP 403/);
      expect((e as Error).message).toMatch(/protocol resolve4\/6:/);
      const cause = (e as Error).cause;
      expect(cause).toBeInstanceOf(AggregateError);
      expect((cause as AggregateError).errors[0]).toMatchObject({ code: "EAI_AGAIN" });
    }
  });
});
