import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { withTempHome } from "../../test/helpers/temp-home.js";
import { readManagedProfile } from "../profiles/managed.js";
import { setupCommand } from "./setup.js";

describe("setupCommand", () => {
  it("writes gateway.mode=local on first run", async () => {
    await withTempHome(async (home) => {
      const runtime = {
        log: vi.fn(),
        error: vi.fn(),
        exit: vi.fn(),
      };
      const workspace = path.join(home, "workspace");

      await setupCommand({ workspace }, runtime);

      const configPath = path.join(home, ".openclaw", "openclaw.json");
      const raw = await fs.readFile(configPath, "utf-8");

      expect(raw).toContain('"mode": "local"');
      expect(raw).toContain(`"workspace": "${workspace}"`);
    });
  });

  it("adds gateway.mode=local to an existing config without overwriting workspace", async () => {
    await withTempHome(async (home) => {
      const runtime = {
        log: vi.fn(),
        error: vi.fn(),
        exit: vi.fn(),
      };
      const configDir = path.join(home, ".openclaw");
      const configPath = path.join(configDir, "openclaw.json");
      const workspace = path.join(home, "custom-workspace");

      await fs.mkdir(configDir, { recursive: true });
      await fs.writeFile(
        configPath,
        JSON.stringify({
          agents: {
            defaults: {
              workspace,
            },
          },
        }),
      );

      await setupCommand(undefined, runtime);

      const raw = JSON.parse(await fs.readFile(configPath, "utf-8")) as {
        agents?: { defaults?: { workspace?: string } };
        gateway?: { mode?: string };
      };

      expect(raw.agents?.defaults?.workspace).toBe(workspace);
      expect(raw.gateway?.mode).toBe("local");
    });
  });

  it("allocates distinct managed profile ports when setup bootstraps multiple profiles", async () => {
    await withTempHome(async (home) => {
      const runtime = {
        log: vi.fn(),
        error: vi.fn(),
        exit: vi.fn(),
      };
      process.env.OPENCLAW_HOME = home;
      delete process.env.OPENCLAW_STATE_DIR;
      delete process.env.OPENCLAW_CONFIG_PATH;
      process.env.OPENCLAW_PROFILE = "work-a";
      await setupCommand({ workspace: path.join(home, "workspace-a") }, runtime);
      process.env.OPENCLAW_PROFILE = "work-b";
      await setupCommand({ workspace: path.join(home, "workspace-b") }, runtime);

      const env = { ...process.env, OPENCLAW_HOME: home } as NodeJS.ProcessEnv;
      const first = await readManagedProfile("work-a", env, () => home);
      const second = await readManagedProfile("work-b", env, () => home);
      expect(first?.basePort).toBeDefined();
      expect(second?.basePort).toBeDefined();
      expect(first?.basePort).not.toBe(second?.basePort);
    });
  });
});
