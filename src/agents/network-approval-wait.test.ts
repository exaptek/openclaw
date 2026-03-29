import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { readResolvedFile, waitForNetworkApprovalResolution } from "./network-approval-wait.js";

describe("network-approval-wait", () => {
  it("reads resolved.json when present", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), "openclaw-netwait-test-"));
    try {
      const id = "abc12345";
      const dir = path.join(root, id);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(
        path.join(dir, "resolved.json"),
        JSON.stringify({ action: "approve" }),
        "utf8",
      );
      await expect(readResolvedFile(root, id)).resolves.toEqual({ action: "approve" });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("times out when resolved never appears", async () => {
    const prev = process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_TIMEOUT_MS;
    process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_TIMEOUT_MS = "300";
    const root = await fs.mkdtemp(path.join(process.cwd(), "openclaw-netwait-timeout-"));
    try {
      const outcome = await waitForNetworkApprovalResolution({
        waitDir: root,
        approvalId: "nope",
      });
      expect(outcome).toBe("timeout");
    } finally {
      if (prev === undefined) {
        delete process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_TIMEOUT_MS;
      } else {
        process.env.OPENCLAW_NETWORK_APPROVAL_WAIT_TIMEOUT_MS = prev;
      }
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
