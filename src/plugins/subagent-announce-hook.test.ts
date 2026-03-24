import { describe, expect, it, vi, beforeEach } from "vitest";

const announceHookMocks = vi.hoisted(() => ({
  mockRunSubagentAnnounce: vi.fn(),
}));

vi.mock("./hook-runner-global.js", () => ({
  getGlobalHookRunner: () => ({
    hasHooks: (name: string) => name === "subagent_announce",
    runSubagentAnnounce: announceHookMocks.mockRunSubagentAnnounce,
  }),
}));

describe("deliverSubagentAnnouncement + subagent_announce hook", () => {
  beforeEach(() => {
    announceHookMocks.mockRunSubagentAnnounce.mockReset();
    // Allow dynamic import() of ../agents/subagent-announce.js to pick up the mock when other unit tests loaded that module first.
    vi.resetModules();
  });

  it("returns path hook when hook suppresses default delivery", async () => {
    announceHookMocks.mockRunSubagentAnnounce.mockResolvedValue({ suppressDefaultDelivery: true });

    const { deliverSubagentAnnouncement } = await import("../agents/subagent-announce.js");

    const result = await deliverSubagentAnnouncement({
      requesterSessionKey: "agent:main:main",
      triggerMessage: "trigger",
      steerMessage: "steer",
      targetRequesterSessionKey: "agent:main:main",
      requesterIsSubagent: false,
      expectsCompletionMessage: true,
      directIdempotencyKey: "idem-1",
    });

    expect(result).toEqual({ delivered: true, path: "hook" });
    expect(announceHookMocks.mockRunSubagentAnnounce).toHaveBeenCalledTimes(1);
  });
});
