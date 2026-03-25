import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readManagedProfile } from "../profiles/managed.js";
import { createNonExitingRuntime } from "../runtime.js";
import {
  profileCloneCommand,
  profileCreateCommand,
  profileDeleteCommand,
  profileDoctorCommand,
  profileImportCommand,
} from "./profile.js";

describe("profile commands", () => {
  const originalHome = process.env.OPENCLAW_HOME;
  const originalProfile = process.env.OPENCLAW_PROFILE;

  beforeEach(() => {
    delete process.env.OPENCLAW_PROFILE;
  });

  afterEach(() => {
    if (originalHome === undefined) {
      delete process.env.OPENCLAW_HOME;
    } else {
      process.env.OPENCLAW_HOME = originalHome;
    }
    if (originalProfile === undefined) {
      delete process.env.OPENCLAW_PROFILE;
    } else {
      process.env.OPENCLAW_PROFILE = originalProfile;
    }
  });

  it("creates a managed profile with manifest, config, state, and workspace", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-create-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();

    await profileCreateCommand(runtime, "rescue", {});

    const profile = await readManagedProfile("rescue", process.env, () => root);
    expect(profile).not.toBeNull();
    expect(profile?.configPath).toBe(
      path.join(root, ".openclaw", "profiles", "rescue", "config", "openclaw.json"),
    );
    expect(await fs.stat(profile!.stateDir)).toBeTruthy();
    expect(await fs.stat(profile!.workspaceDir)).toBeTruthy();
  });

  it("clones a profile with a fresh token and rewritten workspace", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-clone-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();

    await profileCreateCommand(runtime, "source", {});
    const source = await readManagedProfile("source", process.env, () => root);
    if (!source) {
      throw new Error("source profile missing");
    }
    await fs.writeFile(
      source.configPath,
      JSON.stringify(
        {
          agents: { defaults: { workspace: "/tmp/old-workspace" } },
          gateway: { auth: { mode: "token", token: "old-token" } },
        },
        null,
        2,
      ),
      "utf8",
    );
    await fs.mkdir(path.join(source.stateDir, "logs"), { recursive: true });
    await fs.writeFile(path.join(source.stateDir, "logs", "gateway.log"), "noise", "utf8");
    await fs.mkdir(path.join(source.stateDir, "credentials"), { recursive: true });
    await fs.writeFile(path.join(source.stateDir, "credentials", "oauth.json"), "{}", "utf8");
    await fs.mkdir(path.join(source.stateDir, "profiles", "other"), { recursive: true });
    await fs.writeFile(
      path.join(source.stateDir, "profiles", "other", "profile.json"),
      "{}",
      "utf8",
    );
    await fs.mkdir(path.join(source.stateDir, "agents", "main", "agent"), { recursive: true });
    await fs.writeFile(
      path.join(source.stateDir, "agents", "main", "agent", "auth-profiles.json"),
      "{}",
      "utf8",
    );
    await fs.mkdir(path.join(source.stateDir, "agents", "main", "sessions"), { recursive: true });
    await fs.writeFile(
      path.join(source.stateDir, "agents", "main", "sessions", "turn.json"),
      "{}",
      "utf8",
    );

    await profileCloneCommand(runtime, "source", "clone", {});

    const clone = await readManagedProfile("clone", process.env, () => root);
    if (!clone) {
      throw new Error("clone profile missing");
    }
    const cloneConfig = JSON.parse(await fs.readFile(clone.configPath, "utf8")) as {
      agents?: { defaults?: { workspace?: string } };
      gateway?: { auth?: { token?: string } };
    };
    expect(cloneConfig.agents?.defaults?.workspace).toBe(clone.workspaceDir);
    expect(cloneConfig.gateway?.auth?.token).not.toBe("old-token");
    await expect(
      fs.stat(path.join(clone.stateDir, "credentials", "oauth.json")),
    ).resolves.toBeTruthy();
    await expect(
      fs.stat(path.join(clone.stateDir, "agents", "main", "agent", "auth-profiles.json")),
    ).resolves.toBeTruthy();
    await expect(
      fs.stat(path.join(clone.stateDir, "agents", "main", "sessions", "turn.json")),
    ).rejects.toThrow();
    await expect(fs.stat(path.join(clone.stateDir, "profiles"))).rejects.toThrow();
    await expect(fs.stat(path.join(clone.stateDir, "logs"))).rejects.toThrow();
  });

  it("doctor warns when config workspace escapes the managed workspace root", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-doctor-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();

    await profileCreateCommand(runtime, "doctor-test", {});
    const profile = await readManagedProfile("doctor-test", process.env, () => root);
    if (!profile) {
      throw new Error("doctor-test profile missing");
    }
    await fs.writeFile(
      profile.configPath,
      JSON.stringify({ agents: { defaults: { workspace: "/tmp/external" } } }, null, 2),
      "utf8",
    );

    const lines: string[] = [];
    runtime.log = (...args: unknown[]) => {
      lines.push(args.map((arg) => String(arg)).join(" "));
    };

    await profileDoctorCommand(runtime, "doctor-test", { json: false });

    expect(lines.join("\n")).toContain(
      "agents.defaults.workspace diverges from the managed profile workspace",
    );
  });

  it("imports a legacy named profile without changing its effective roots", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-import-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();
    const legacyRoot = path.join(root, ".openclaw-legacy");
    await fs.mkdir(path.join(legacyRoot, "credentials"), { recursive: true });
    await fs.writeFile(
      path.join(legacyRoot, "openclaw.json"),
      JSON.stringify({ agents: { defaults: { workspace: "/tmp/legacy" } } }, null, 2),
      "utf8",
    );
    await fs.writeFile(path.join(legacyRoot, "credentials", "oauth.json"), "{}", "utf8");

    await profileImportCommand(runtime, "legacy", {});

    const managed = await readManagedProfile("legacy", process.env, () => root);
    expect(managed).not.toBeNull();
    expect(managed?.mode).toBe("adopted-legacy");
    expect(managed?.stateDir).toBe(legacyRoot);
    expect(managed?.configPath).toBe(path.join(legacyRoot, "openclaw.json"));
    await expect(fs.stat(path.join(legacyRoot, "credentials", "oauth.json"))).resolves.toBeTruthy();
  });

  it("refuses to create a managed profile when a same-id legacy profile exists", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-shadow-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();
    await fs.mkdir(path.join(root, ".openclaw-shadow"), { recursive: true });

    await expect(profileCreateCommand(runtime, "shadow", {})).rejects.toThrow(
      /profile import shadow/i,
    );
  });

  it("refuses to clone into a destination id already used by a legacy profile", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-clone-shadow-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();

    await profileCreateCommand(runtime, "source", {});
    await fs.mkdir(path.join(root, ".openclaw-shadow"), { recursive: true });

    await expect(profileCloneCommand(runtime, "source", "shadow", {})).rejects.toThrow(
      /profile import shadow/i,
    );
  });

  it("refuses to delete the active profile without force", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-delete-"));
    process.env.OPENCLAW_HOME = root;
    process.env.OPENCLAW_PROFILE = "active";
    const runtime = createNonExitingRuntime();

    await profileCreateCommand(runtime, "active", {});

    await expect(profileDeleteCommand(runtime, "active", { yes: true })).rejects.toThrow(
      /live profile|active CLI environment/i,
    );
  });

  it("refuses to delete a profile when the active env points at its config/state roots", async () => {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-profile-delete-override-"));
    process.env.OPENCLAW_HOME = root;
    const runtime = createNonExitingRuntime();

    await profileCreateCommand(runtime, "override", {});
    const profile = await readManagedProfile("override", process.env, () => root);
    if (!profile) {
      throw new Error("override profile missing");
    }

    delete process.env.OPENCLAW_PROFILE;
    process.env.OPENCLAW_STATE_DIR = profile.stateDir;

    await expect(profileDeleteCommand(runtime, "override", { yes: true })).rejects.toThrow(
      /state dir matches the active CLI environment/i,
    );
  });
});
