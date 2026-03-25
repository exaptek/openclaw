import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { writeManagedProfileSpec, createProfileSpec } from "../profiles/managed.js";
import { withTempDir } from "../test-helpers/temp-dir.js";
import {
  resolveDefaultConfigCandidates,
  resolveConfigPathCandidate,
  resolveConfigPath,
  resolveGatewayPort,
  resolveOAuthDir,
  resolveOAuthPath,
  resolveStateDir,
} from "./paths.js";

describe("oauth paths", () => {
  it("prefers OPENCLAW_OAUTH_DIR over OPENCLAW_STATE_DIR", () => {
    const env = {
      OPENCLAW_OAUTH_DIR: "/custom/oauth",
      OPENCLAW_STATE_DIR: "/custom/state",
    } as NodeJS.ProcessEnv;

    expect(resolveOAuthDir(env, "/custom/state")).toBe(path.resolve("/custom/oauth"));
    expect(resolveOAuthPath(env, "/custom/state")).toBe(
      path.join(path.resolve("/custom/oauth"), "oauth.json"),
    );
  });

  it("derives oauth path from OPENCLAW_STATE_DIR when unset", () => {
    const env = {
      OPENCLAW_STATE_DIR: "/custom/state",
    } as NodeJS.ProcessEnv;

    expect(resolveOAuthDir(env, "/custom/state")).toBe(path.join("/custom/state", "credentials"));
    expect(resolveOAuthPath(env, "/custom/state")).toBe(
      path.join("/custom/state", "credentials", "oauth.json"),
    );
  });
});

describe("state + config path candidates", () => {
  function expectOpenClawHomeDefaults(env: NodeJS.ProcessEnv): void {
    const configuredHome = env.OPENCLAW_HOME;
    if (!configuredHome) {
      throw new Error("OPENCLAW_HOME must be set for this assertion helper");
    }
    const resolvedHome = path.resolve(configuredHome);
    expect(resolveStateDir(env)).toBe(path.join(resolvedHome, ".openclaw"));

    const candidates = resolveDefaultConfigCandidates(env);
    expect(candidates[0]).toBe(path.join(resolvedHome, ".openclaw", "openclaw.json"));
  }

  it("uses OPENCLAW_STATE_DIR when set", () => {
    const env = {
      OPENCLAW_STATE_DIR: "/new/state",
    } as NodeJS.ProcessEnv;

    expect(resolveStateDir(env, () => "/home/test")).toBe(path.resolve("/new/state"));
  });

  it("uses OPENCLAW_HOME for default state/config locations", () => {
    const env = {
      OPENCLAW_HOME: "/srv/openclaw-home",
    } as NodeJS.ProcessEnv;
    expectOpenClawHomeDefaults(env);
  });

  it("prefers OPENCLAW_HOME over HOME for default state/config locations", () => {
    const env = {
      OPENCLAW_HOME: "/srv/openclaw-home",
      HOME: "/home/other",
    } as NodeJS.ProcessEnv;
    expectOpenClawHomeDefaults(env);
  });

  it("orders default config candidates in a stable order", () => {
    const home = "/home/test";
    const resolvedHome = path.resolve(home);
    const candidates = resolveDefaultConfigCandidates({} as NodeJS.ProcessEnv, () => home);
    const expected = [
      path.join(resolvedHome, ".openclaw", "openclaw.json"),
      path.join(resolvedHome, ".openclaw", "clawdbot.json"),
      path.join(resolvedHome, ".openclaw", "moldbot.json"),
      path.join(resolvedHome, ".clawdbot", "openclaw.json"),
      path.join(resolvedHome, ".clawdbot", "clawdbot.json"),
      path.join(resolvedHome, ".clawdbot", "moldbot.json"),
      path.join(resolvedHome, ".moldbot", "openclaw.json"),
      path.join(resolvedHome, ".moldbot", "clawdbot.json"),
      path.join(resolvedHome, ".moldbot", "moldbot.json"),
    ];
    expect(candidates).toEqual(expected);
  });

  it("prefers ~/.openclaw when it exists and legacy dir is missing", async () => {
    await withTempDir({ prefix: "openclaw-state-" }, async (root) => {
      const newDir = path.join(root, ".openclaw");
      await fs.mkdir(newDir, { recursive: true });
      const resolved = resolveStateDir({} as NodeJS.ProcessEnv, () => root);
      expect(resolved).toBe(newDir);
    });
  });

  it("falls back to existing legacy state dir when ~/.openclaw is missing", async () => {
    await withTempDir({ prefix: "openclaw-state-legacy-" }, async (root) => {
      const legacyDir = path.join(root, ".clawdbot");
      await fs.mkdir(legacyDir, { recursive: true });
      const resolved = resolveStateDir({} as NodeJS.ProcessEnv, () => root);
      expect(resolved).toBe(legacyDir);
    });
  });

  it("CONFIG_PATH prefers existing config when present", async () => {
    await withTempDir({ prefix: "openclaw-config-" }, async (root) => {
      const legacyDir = path.join(root, ".openclaw");
      await fs.mkdir(legacyDir, { recursive: true });
      const legacyPath = path.join(legacyDir, "openclaw.json");
      await fs.writeFile(legacyPath, "{}", "utf-8");

      const resolved = resolveConfigPathCandidate({} as NodeJS.ProcessEnv, () => root);
      expect(resolved).toBe(legacyPath);
    });
  });

  it("respects state dir overrides when config is missing", async () => {
    await withTempDir({ prefix: "openclaw-config-override-" }, async (root) => {
      const legacyDir = path.join(root, ".openclaw");
      await fs.mkdir(legacyDir, { recursive: true });
      const legacyConfig = path.join(legacyDir, "openclaw.json");
      await fs.writeFile(legacyConfig, "{}", "utf-8");

      const overrideDir = path.join(root, "override");
      const env = { OPENCLAW_STATE_DIR: overrideDir } as NodeJS.ProcessEnv;
      const resolved = resolveConfigPath(env, overrideDir, () => root);
      expect(resolved).toBe(path.join(overrideDir, "openclaw.json"));
    });
  });

  it("resolves managed profile state and config paths from OPENCLAW_PROFILE", async () => {
    await withTempDir({ prefix: "openclaw-managed-profile-" }, async (root) => {
      const env = {
        OPENCLAW_HOME: root,
        OPENCLAW_PROFILE: "rescue",
      } as NodeJS.ProcessEnv;
      await writeManagedProfileSpec(
        createProfileSpec({
          id: "rescue",
          basePort: 19789,
        }),
        env,
        () => root,
      );

      expect(resolveStateDir(env, () => root)).toBe(
        path.join(root, ".openclaw", "profiles", "rescue", "state"),
      );
      expect(
        resolveConfigPath(
          env,
          resolveStateDir(env, () => root),
          () => root,
        ),
      ).toBe(path.join(root, ".openclaw", "profiles", "rescue", "config", "openclaw.json"));
      expect(resolveDefaultConfigCandidates(env, () => root)).toEqual([
        path.join(root, ".openclaw", "profiles", "rescue", "config", "openclaw.json"),
      ]);
    });
  });

  it("keeps explicit state-dir config precedence even when a profile is selected", async () => {
    await withTempDir({ prefix: "openclaw-profile-state-override-" }, async (root) => {
      const overrideDir = path.join(root, "override");
      const env = {
        OPENCLAW_HOME: root,
        OPENCLAW_PROFILE: "rescue",
        OPENCLAW_STATE_DIR: overrideDir,
      } as NodeJS.ProcessEnv;
      await writeManagedProfileSpec(
        createProfileSpec({
          id: "rescue",
          basePort: 19789,
        }),
        env,
        () => root,
      );

      expect(resolveStateDir(env, () => root)).toBe(overrideDir);
      expect(resolveConfigPath(env, overrideDir, () => root)).toBe(
        path.join(overrideDir, "openclaw.json"),
      );
      expect(resolveDefaultConfigCandidates(env, () => root)).toEqual([
        path.join(overrideDir, "openclaw.json"),
        path.join(overrideDir, "clawdbot.json"),
        path.join(overrideDir, "moldbot.json"),
      ]);
    });
  });

  it("preserves a legacy profile's configured gateway port over profile defaults", async () => {
    await withTempDir({ prefix: "openclaw-legacy-port-" }, async (root) => {
      const legacyDir = path.join(root, ".openclaw-work");
      await fs.mkdir(legacyDir, { recursive: true });
      await fs.writeFile(
        path.join(legacyDir, "openclaw.json"),
        JSON.stringify({ gateway: { port: 19555 } }),
        "utf8",
      );

      const env = {
        OPENCLAW_HOME: root,
        OPENCLAW_PROFILE: "work",
      } as NodeJS.ProcessEnv;
      expect(resolveGatewayPort(undefined, env)).toBe(19555);
    });
  });

  it("does not fall back to a profile port when config/state paths are explicitly overridden", async () => {
    await withTempDir({ prefix: "openclaw-profile-port-override-" }, async (root) => {
      const env = {
        OPENCLAW_HOME: root,
        OPENCLAW_PROFILE: "dev",
        OPENCLAW_STATE_DIR: path.join(root, "override-state"),
      } as NodeJS.ProcessEnv;
      expect(resolveGatewayPort(undefined, env)).toBe(18789);
    });
  });
});
