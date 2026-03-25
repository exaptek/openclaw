import { createHash } from "node:crypto";
import fsp from "node:fs/promises";
import path from "node:path";
import JSON5 from "json5";
import { resolveGatewayLockDir } from "../config/paths.js";
import { resolveGatewayService } from "../daemon/service.js";
import { writeJsonAtomic } from "../infra/json-files.js";
import {
  createProfileSpec,
  importLegacyProfile,
  listProfiles,
  normalizeProfileId,
  readManagedProfile,
  resolveManagedProfileRoot,
  resolveProfileSelection,
  suggestProfileBasePort,
  type ProfileSpec,
  type ResolvedProfile,
  writeManagedProfileSpec,
} from "../profiles/managed.js";
import type { OutputRuntimeEnv } from "../runtime.js";
import { writeRuntimeJson } from "../runtime.js";
import { isPidAlive } from "../shared/pid-alive.js";
import { randomToken } from "./onboard-helpers.js";

const PROFILE_TOP_LEVEL_EXCLUDES = new Set([
  "browser",
  "canvas",
  "completions",
  "cron",
  "delivery-queue",
  "devices",
  "heartbeat-policy",
  "identity",
  "logs",
  "profiles",
  "subagents",
]);

const PROFILE_FILE_EXCLUDES = new Set([
  "openclaw.json",
  "openclaw.json.bak",
  "openclaw.json.bak.1",
  "openclaw.json.bak.2",
  "openclaw.json.bak.3",
  "openclaw.json.bak.4",
  "update-check.json",
]);

type MutableRecord = Record<string, unknown>;

function ensureProfileInsideRoot(profile: ResolvedProfile, target: string): boolean {
  const relative = path.relative(profile.profileRoot, target);
  return !(relative.startsWith("..") || path.isAbsolute(relative));
}

function normalizeConfigObject(raw: unknown): MutableRecord {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }
  return raw as MutableRecord;
}

async function readConfigObject(filePath: string): Promise<MutableRecord> {
  try {
    const raw = await fsp.readFile(filePath, "utf8");
    return normalizeConfigObject(JSON5.parse(raw));
  } catch {
    return {};
  }
}

function withRecord(value: unknown): MutableRecord {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as MutableRecord)
    : {};
}

function prepareConfigForProfile(params: {
  config: MutableRecord;
  destination: ResolvedProfile;
  operation: "create" | "clone";
}): MutableRecord {
  const next = structuredClone(params.config);
  const agents = withRecord(next.agents);
  const defaults = withRecord(agents.defaults);
  defaults.workspace = params.destination.workspaceDir;
  agents.defaults = defaults;
  next.agents = agents;

  const gateway = withRecord(next.gateway);
  const auth = withRecord(gateway.auth);
  const mode = typeof auth.mode === "string" ? auth.mode : undefined;
  const hasPassword = typeof auth.password === "string" && auth.password.trim().length > 0;
  if (params.operation === "clone" && (!hasPassword || mode === "token" || mode === undefined)) {
    auth.mode = "token";
    auth.token = randomToken();
    gateway.auth = auth;
  }
  gateway.port = params.destination.basePort;
  next.gateway = gateway;

  return next;
}

function classifyStateEntry(relativePath: string): "copy" | "skip" {
  const normalized = relativePath.split(path.sep).filter(Boolean);
  if (normalized.length === 0) {
    return "copy";
  }
  if (PROFILE_FILE_EXCLUDES.has(normalized.at(-1) ?? "")) {
    return "skip";
  }
  if (PROFILE_TOP_LEVEL_EXCLUDES.has(normalized[0] ?? "")) {
    return "skip";
  }
  if (normalized[0] === "agents" && normalized.includes("sessions")) {
    return "skip";
  }
  return "copy";
}

async function copyProfileStateTree(params: {
  sourceRoot: string;
  destinationRoot: string;
  relative?: string;
}) {
  const relative = params.relative ?? "";
  const sourceRoot = relative ? path.join(params.sourceRoot, relative) : params.sourceRoot;
  const destinationRoot = relative
    ? path.join(params.destinationRoot, relative)
    : params.destinationRoot;
  await fsp.mkdir(destinationRoot, { recursive: true, mode: 0o700 });
  const entries = await fsp.readdir(sourceRoot, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const childRelative = relative ? path.join(relative, entry.name) : entry.name;
    if (classifyStateEntry(childRelative) === "skip") {
      continue;
    }
    const srcPath = path.join(params.sourceRoot, childRelative);
    const dstPath = path.join(params.destinationRoot, childRelative);
    if (entry.isDirectory()) {
      await copyProfileStateTree({
        sourceRoot: params.sourceRoot,
        destinationRoot: params.destinationRoot,
        relative: childRelative,
      });
      continue;
    }
    if (entry.isFile()) {
      await fsp.mkdir(path.dirname(dstPath), { recursive: true, mode: 0o700 });
      await fsp.copyFile(srcPath, dstPath);
    }
  }
}

async function chooseBasePort(profileId: string, from?: string): Promise<number> {
  const id = normalizeProfileId(profileId);
  if (!from) {
    if (id === "default") {
      return 18789;
    }
    if (id === "dev") {
      return 19001;
    }
  }
  return suggestProfileBasePort();
}

function formatProfileSummary(profile: ResolvedProfile) {
  return {
    id: profile.id,
    kind: profile.kind,
    mode: profile.mode,
    managed: profile.managed,
    exists: profile.exists,
    profileRoot: profile.profileRoot,
    manifestPath: profile.manifestPath,
    configPath: profile.configPath,
    stateDir: profile.stateDir,
    workspaceDir: profile.workspaceDir,
    basePort: profile.basePort,
    effectiveGatewayPort: profile.effectiveGatewayPort,
    configuredGatewayPort: profile.configuredGatewayPort,
    createdAt: profile.createdAt,
    createdFrom: profile.createdFrom,
    adoptedFromLegacy: profile.adoptedFromLegacy,
    warnings: profile.warnings,
  };
}

async function buildDoctorReport(profile: ResolvedProfile) {
  const warnings = [...profile.warnings];
  const config = await readConfigObject(profile.configPath);
  const agents = withRecord(config.agents);
  const defaults = withRecord(agents.defaults);
  const configuredWorkspace =
    typeof defaults.workspace === "string" && defaults.workspace.trim().length > 0
      ? path.resolve(defaults.workspace)
      : null;
  if (configuredWorkspace && configuredWorkspace !== path.resolve(profile.workspaceDir)) {
    warnings.push(
      `agents.defaults.workspace diverges from the managed profile workspace (configured: ${configuredWorkspace}, expected: ${path.resolve(profile.workspaceDir)})`,
    );
  }
  const gateway = withRecord(config.gateway);
  const configPort = gateway.port;
  if (
    typeof configPort === "number" &&
    Number.isFinite(configPort) &&
    configPort > 0 &&
    configPort !== profile.effectiveGatewayPort
  ) {
    warnings.push(
      `gateway.port (${configPort}) diverges from effectiveGatewayPort (${profile.effectiveGatewayPort})`,
    );
  }
  if (profile.managed && profile.mode === "managed-native") {
    if (!ensureProfileInsideRoot(profile, profile.stateDir)) {
      warnings.push("state dir escapes the profile root");
    }
    if (!ensureProfileInsideRoot(profile, profile.configPath)) {
      warnings.push("config path escapes the profile root");
    }
    if (!ensureProfileInsideRoot(profile, profile.workspaceDir)) {
      warnings.push("workspace path escapes the profile root");
    }
  }
  if (profile.mode === "legacy-unmanaged") {
    warnings.push("legacy profile is not yet managed by profile.json");
  }
  return {
    ...formatProfileSummary(profile),
    warnings,
    healthy: warnings.length === 0,
  };
}

function writeProfileOutput(runtime: OutputRuntimeEnv, value: unknown, json: boolean) {
  if (json) {
    writeRuntimeJson(runtime, value);
    return;
  }
  runtime.log(JSON.stringify(value, null, 2));
}

function buildProfileEnv(profile: ResolvedProfile): Record<string, string> {
  return {
    ...process.env,
    OPENCLAW_PROFILE: profile.id,
    OPENCLAW_STATE_DIR: profile.stateDir,
    OPENCLAW_CONFIG_PATH: profile.configPath,
    OPENCLAW_GATEWAY_PORT: String(profile.effectiveGatewayPort),
  } as Record<string, string>;
}

function resolveGatewayLockPathForProfile(profile: ResolvedProfile): string {
  const hash = createHash("sha256").update(profile.configPath).digest("hex").slice(0, 8);
  return path.join(resolveGatewayLockDir(), `gateway.${hash}.lock`);
}

async function detectLiveProfileReason(profile: ResolvedProfile): Promise<string | null> {
  if (process.env.OPENCLAW_PROFILE?.trim() === profile.id) {
    return "profile matches the active CLI environment";
  }
  const activeStateDir = process.env.OPENCLAW_STATE_DIR?.trim();
  if (activeStateDir && path.resolve(activeStateDir) === path.resolve(profile.stateDir)) {
    return "profile state dir matches the active CLI environment";
  }
  const activeConfigPath = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (activeConfigPath && path.resolve(activeConfigPath) === path.resolve(profile.configPath)) {
    return "profile config path matches the active CLI environment";
  }

  try {
    const service = resolveGatewayService();
    const env = buildProfileEnv(profile);
    if (await service.isLoaded({ env })) {
      const runtime = await service.readRuntime(env);
      if (runtime.status === "running" || runtime.state === "running") {
        return "gateway service is installed and running";
      }
      if (typeof runtime.pid === "number" && runtime.pid > 0 && isPidAlive(runtime.pid)) {
        return `gateway service runtime pid ${runtime.pid} is alive`;
      }
    }
  } catch {
    // Best effort only; fall through to lock inspection.
  }

  try {
    const raw = await fsp.readFile(resolveGatewayLockPathForProfile(profile), "utf8");
    const parsed = JSON.parse(raw) as { pid?: number };
    if (typeof parsed.pid === "number" && parsed.pid > 0 && isPidAlive(parsed.pid)) {
      return `gateway lock is owned by live pid ${parsed.pid}`;
    }
  } catch {
    // No lock or unreadable lock.
  }

  return null;
}

export async function profileListCommand(
  runtime: OutputRuntimeEnv,
  opts: { json?: boolean },
): Promise<void> {
  const profiles = await listProfiles();
  writeProfileOutput(runtime, { items: profiles.map(formatProfileSummary) }, Boolean(opts.json));
}

export async function profileGetCommand(
  runtime: OutputRuntimeEnv,
  profileId: string,
  opts: { json?: boolean },
): Promise<void> {
  const profile = await resolveProfileSelection(profileId);
  writeProfileOutput(runtime, formatProfileSummary(profile), Boolean(opts.json));
}

export async function profilePathsCommand(
  runtime: OutputRuntimeEnv,
  profileId: string,
  opts: { json?: boolean },
): Promise<void> {
  const profile = await resolveProfileSelection(profileId);
  writeProfileOutput(
    runtime,
    {
      id: profile.id,
      profileRoot: profile.profileRoot,
      manifestPath: profile.manifestPath,
      configPath: profile.configPath,
      stateDir: profile.stateDir,
      workspaceDir: profile.workspaceDir,
    },
    Boolean(opts.json),
  );
}

export async function profileCreateCommand(
  runtime: OutputRuntimeEnv,
  profileId: string,
  opts: { json?: boolean },
): Promise<void> {
  const id = normalizeProfileId(profileId);
  const existingManaged = await readManagedProfile(id);
  if (existingManaged) {
    throw new Error(`Managed profile already exists: ${id}`);
  }
  const existingSelection = await resolveProfileSelection(id);
  if (existingSelection.mode === "legacy-unmanaged") {
    throw new Error(
      `Legacy profile already exists: ${id}. Use "openclaw profile import ${id}" instead.`,
    );
  }

  const basePort = await chooseBasePort(id);
  const spec: ProfileSpec = createProfileSpec({ id, basePort });
  const destination = await writeManagedProfileSpec(spec);
  const freshConfig = prepareConfigForProfile({
    config: {},
    destination,
    operation: "create",
  });
  await writeJsonAtomic(destination.configPath, freshConfig, {
    mode: 0o600,
    trailingNewline: true,
    ensureDirMode: 0o700,
  });

  writeProfileOutput(runtime, formatProfileSummary(destination), Boolean(opts.json));
}

export async function profileCloneCommand(
  runtime: OutputRuntimeEnv,
  sourceId: string,
  profileId: string,
  opts: { json?: boolean },
): Promise<void> {
  const id = normalizeProfileId(profileId);
  const existingManaged = await readManagedProfile(id);
  if (existingManaged) {
    throw new Error(`Managed profile already exists: ${id}`);
  }
  const existingSelection = await resolveProfileSelection(id);
  if (existingSelection.mode === "legacy-unmanaged") {
    throw new Error(
      `Legacy profile already exists: ${id}. Use "openclaw profile import ${id}" instead.`,
    );
  }

  const source = await resolveProfileSelection(sourceId);
  if (!source.exists) {
    throw new Error(`Source profile not found: ${normalizeProfileId(sourceId)}`);
  }

  const basePort = await chooseBasePort(id, source.id);
  const spec: ProfileSpec = createProfileSpec({
    id,
    basePort,
    createdFrom: source.id,
  });
  const destination = await writeManagedProfileSpec(spec);

  const sourceConfig = await readConfigObject(source.configPath);
  const nextConfig = prepareConfigForProfile({
    config: sourceConfig,
    destination,
    operation: "clone",
  });
  await writeJsonAtomic(destination.configPath, nextConfig, {
    mode: 0o600,
    trailingNewline: true,
    ensureDirMode: 0o700,
  });
  await copyProfileStateTree({
    sourceRoot: source.stateDir,
    destinationRoot: destination.stateDir,
  });

  writeProfileOutput(runtime, formatProfileSummary(destination), Boolean(opts.json));
}

export async function profileImportCommand(
  runtime: OutputRuntimeEnv,
  profileId: string,
  opts: { json?: boolean },
): Promise<void> {
  const profile = await importLegacyProfile(profileId);
  writeProfileOutput(runtime, formatProfileSummary(profile), Boolean(opts.json));
}

export async function profileDoctorCommand(
  runtime: OutputRuntimeEnv,
  profileId: string,
  opts: { json?: boolean },
): Promise<void> {
  const profile = await resolveProfileSelection(profileId);
  const report = await buildDoctorReport(profile);
  writeProfileOutput(runtime, report, Boolean(opts.json));
}

export async function profileDeleteCommand(
  runtime: OutputRuntimeEnv,
  profileId: string,
  opts: { yes?: boolean; force?: boolean; json?: boolean },
): Promise<void> {
  const id = normalizeProfileId(profileId);
  const profile = await readManagedProfile(id);
  if (!profile) {
    throw new Error(`Managed profile not found: ${id}`);
  }
  if (!opts.yes) {
    throw new Error("profile delete requires --yes");
  }
  const liveReason = await detectLiveProfileReason(profile);
  if (liveReason && !opts.force) {
    throw new Error(`Refusing to delete a live profile: ${liveReason}`);
  }
  await fsp.rm(resolveManagedProfileRoot(id), { recursive: true, force: true });
  writeProfileOutput(runtime, { ok: true, deleted: id }, Boolean(opts.json));
}
