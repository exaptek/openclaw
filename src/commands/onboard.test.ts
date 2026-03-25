import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { withTempHome } from "../../test/helpers/temp-home.js";
import { applyCliProfileEnv } from "../cli/profile.js";
import { readManagedProfile } from "../profiles/managed.js";
import type { RuntimeEnv } from "../runtime.js";

const mocks = vi.hoisted(() => ({
  runInteractiveSetup: vi.fn(async () => {}),
  runNonInteractiveSetup: vi.fn(async () => {}),
  readConfigFileSnapshot: vi.fn(async () => ({ exists: false, valid: false, config: {} })),
  handleReset: vi.fn(async () => {}),
}));

vi.mock("./onboard-interactive.js", () => ({
  runInteractiveSetup: mocks.runInteractiveSetup,
}));

vi.mock("./onboard-non-interactive.js", () => ({
  runNonInteractiveSetup: mocks.runNonInteractiveSetup,
}));

vi.mock("../config/config.js", () => ({
  readConfigFileSnapshot: mocks.readConfigFileSnapshot,
}));

vi.mock("./onboard-helpers.js", () => ({
  DEFAULT_WORKSPACE: "~/.openclaw/workspace",
  handleReset: mocks.handleReset,
}));

const { onboardCommand, setupWizardCommand } = await import("./onboard.js");

function makeRuntime(): RuntimeEnv {
  return {
    log: vi.fn(),
    error: vi.fn(),
    exit: vi.fn() as unknown as RuntimeEnv["exit"],
  };
}

describe("setupWizardCommand", () => {
  afterEach(() => {
    vi.clearAllMocks();
    mocks.readConfigFileSnapshot.mockResolvedValue({ exists: false, valid: false, config: {} });
  });

  it("fails fast for invalid secret-input-mode before setup starts", async () => {
    const runtime = makeRuntime();

    await setupWizardCommand(
      {
        secretInputMode: "invalid" as never, // pragma: allowlist secret
      },
      runtime,
    );

    expect(runtime.error).toHaveBeenCalledWith(
      'Invalid --secret-input-mode. Use "plaintext" or "ref".',
    );
    expect(runtime.exit).toHaveBeenCalledWith(1);
    expect(mocks.runInteractiveSetup).not.toHaveBeenCalled();
    expect(mocks.runNonInteractiveSetup).not.toHaveBeenCalled();
  });

  it("logs ASCII-safe Windows guidance before setup", async () => {
    const runtime = makeRuntime();
    const platformSpy = vi.spyOn(process, "platform", "get").mockReturnValue("win32");

    try {
      await setupWizardCommand({}, runtime);

      expect(runtime.log).toHaveBeenCalledWith(
        [
          "Windows detected - OpenClaw runs great on WSL2!",
          "Native Windows might be trickier.",
          "Quick setup: wsl --install (one command, one reboot)",
          "Guide: https://docs.openclaw.ai/windows",
        ].join("\n"),
      );
    } finally {
      platformSpy.mockRestore();
    }
  });

  it("defaults --reset to config+creds+sessions scope", async () => {
    const runtime = makeRuntime();

    await setupWizardCommand(
      {
        reset: true,
      },
      runtime,
    );

    expect(mocks.handleReset).toHaveBeenCalledWith(
      "config+creds+sessions",
      expect.any(String),
      runtime,
    );
  });

  it("uses configured default workspace for --reset when --workspace is not provided", async () => {
    const runtime = makeRuntime();
    mocks.readConfigFileSnapshot.mockResolvedValue({
      exists: true,
      valid: true,
      config: {
        agents: {
          defaults: {
            workspace: "/tmp/openclaw-custom-workspace",
          },
        },
      },
    });

    await setupWizardCommand(
      {
        reset: true,
      },
      runtime,
    );

    expect(mocks.handleReset).toHaveBeenCalledWith(
      "config+creds+sessions",
      path.resolve("/tmp/openclaw-custom-workspace"),
      runtime,
    );
  });

  it("accepts explicit --reset-scope full", async () => {
    const runtime = makeRuntime();

    await setupWizardCommand(
      {
        reset: true,
        resetScope: "full",
      },
      runtime,
    );

    expect(mocks.handleReset).toHaveBeenCalledWith("full", expect.any(String), runtime);
  });

  it("bootstraps a managed profile when onboard runs with auto-filled profile paths", async () => {
    await withTempHome(async (home) => {
      const runtime = makeRuntime();
      process.env.OPENCLAW_HOME = home;
      delete process.env.OPENCLAW_STATE_DIR;
      delete process.env.OPENCLAW_CONFIG_PATH;
      delete process.env.OPENCLAW_GATEWAY_PORT;
      applyCliProfileEnv({
        profile: "onboard-auto",
        env: process.env as Record<string, string | undefined>,
        homedir: () => home,
      });

      await setupWizardCommand({}, runtime);

      const profile = await readManagedProfile("onboard-auto", process.env, () => home);
      expect(profile?.managed).toBe(true);
      expect(mocks.runInteractiveSetup).toHaveBeenCalled();
    });
  });

  it("fails fast for invalid --reset-scope", async () => {
    const runtime = makeRuntime();

    await setupWizardCommand(
      {
        reset: true,
        resetScope: "invalid" as never,
      },
      runtime,
    );

    expect(runtime.error).toHaveBeenCalledWith(
      'Invalid --reset-scope. Use "config", "config+creds+sessions", or "full".',
    );
    expect(runtime.exit).toHaveBeenCalledWith(1);
    expect(mocks.handleReset).not.toHaveBeenCalled();
    expect(mocks.runInteractiveSetup).not.toHaveBeenCalled();
    expect(mocks.runNonInteractiveSetup).not.toHaveBeenCalled();
  });

  it("keeps onboardCommand as an alias for setupWizardCommand", () => {
    expect(onboardCommand).toBe(setupWizardCommand);
  });
});
