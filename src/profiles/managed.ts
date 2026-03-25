import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import JSON5 from "json5";
import { normalizeProfileName } from "../cli/profile-utils.js";
import { resolveRequiredHomeDir } from "../infra/home-dir.js";
import { readJsonFile, writeJsonAtomic } from "../infra/json-files.js";

export const PROFILE_SCHEMA_VERSION = 1;
export const DEFAULT_PROFILE_ID = "default";
export const DEFAULT_PROFILE_ROOT_BASENAME = ".openclaw";
const CONFIG_FILENAME = "openclaw.json";
// Includes the canonical filename because legacy profile resolution searches
// for the active config path directly, unlike config/paths.ts candidate ordering.
const LEGACY_CONFIG_FILENAMES = ["openclaw.json", "clawdbot.json", "moldbot.json"] as const;
const LEGACY_STATE_DIRNAMES = [".openclaw", ".clawdbot", ".moldbot"] as const;
const PROFILE_SUBDIR = "profiles";

export type ProfileSpec = {
  schemaVersion: number;
  id: string;
  roots: {
    config: string;
    state: string;
    workspace: string;
  };
  network: {
    basePort: number;
  };
  createdAt: string;
  createdFrom?: string;
  adoptedFromLegacy?: string;
};

export type ResolvedProfileMode =
  | "managed-native"
  | "adopted-legacy"
  | "legacy-unmanaged"
  | "implicit-default"
  | "implicit-managed";

export type ResolvedProfile = {
  id: string;
  kind: "managed" | "legacy" | "implicit";
  mode: ResolvedProfileMode;
  profileRoot: string;
  manifestPath: string;
  configPath: string;
  stateDir: string;
  workspaceDir: string;
  basePort: number;
  effectiveGatewayPort: number;
  configuredGatewayPort?: number;
  exists: boolean;
  managed: boolean;
  createdFrom?: string;
  createdAt?: string;
  adoptedFromLegacy?: string;
  warnings: string[];
};

function envHomedir(env: NodeJS.ProcessEnv): () => string {
  return () => resolveRequiredHomeDir(env, os.homedir);
}

function resolveManagedProfilesHome(
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  return path.join(
    resolveRequiredHomeDir(env, homedir),
    DEFAULT_PROFILE_ROOT_BASENAME,
    PROFILE_SUBDIR,
  );
}

export function resolveManagedProfileRoot(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  return path.join(resolveManagedProfilesHome(env, homedir), normalizeProfileId(profileId));
}

export function resolveManagedProfileManifestPath(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  return path.join(resolveManagedProfileRoot(profileId, env, homedir), "profile.json");
}

export function normalizeProfileId(raw?: string | null): string {
  return normalizeProfileName(raw) ?? DEFAULT_PROFILE_ID;
}

function resolveProfileComponentPath(profileRoot: string, value: string): string {
  if (path.isAbsolute(value)) {
    return path.resolve(value);
  }
  const resolved = path.resolve(profileRoot, value);
  const relative = path.relative(profileRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Profile path escapes root: ${value}`);
  }
  return resolved;
}

function resolveDefaultBasePort(profileId: string): number {
  const id = normalizeProfileId(profileId);
  if (id === "dev") {
    return 19001;
  }
  return 18789;
}

function readGatewayPortFromConfigObject(raw: unknown): number | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return undefined;
  }
  const gateway = (raw as Record<string, unknown>).gateway;
  if (!gateway || typeof gateway !== "object" || Array.isArray(gateway)) {
    return undefined;
  }
  const port = (gateway as Record<string, unknown>).port;
  return typeof port === "number" && Number.isFinite(port) && port > 0 ? port : undefined;
}

async function readGatewayPortFromConfig(configPath: string): Promise<number | undefined> {
  try {
    const raw = await fsp.readFile(configPath, "utf8");
    return readGatewayPortFromConfigObject(JSON5.parse(raw));
  } catch {
    return undefined;
  }
}

function readGatewayPortFromConfigSync(configPath: string): number | undefined {
  try {
    const raw = fs.readFileSync(configPath, "utf8");
    return readGatewayPortFromConfigObject(JSON5.parse(raw));
  } catch {
    return undefined;
  }
}

function validateProfileSpec(raw: unknown): ProfileSpec | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const spec = raw as Partial<ProfileSpec>;
  if (spec.schemaVersion !== PROFILE_SCHEMA_VERSION || typeof spec.id !== "string") {
    return null;
  }
  if (
    !spec.roots ||
    typeof spec.roots.config !== "string" ||
    typeof spec.roots.state !== "string" ||
    typeof spec.roots.workspace !== "string"
  ) {
    return null;
  }
  if (!spec.network || typeof spec.network.basePort !== "number") {
    return null;
  }
  if (typeof spec.createdAt !== "string") {
    return null;
  }
  return spec as ProfileSpec;
}

async function loadManagedProfileSpec(manifestPath: string): Promise<ProfileSpec | null> {
  return validateProfileSpec(await readJsonFile<ProfileSpec>(manifestPath));
}

function loadManagedProfileSpecSync(manifestPath: string): ProfileSpec | null {
  try {
    return validateProfileSpec(JSON.parse(fs.readFileSync(manifestPath, "utf8")));
  } catch {
    return null;
  }
}

function buildResolvedProfile(params: {
  id: string;
  kind: ResolvedProfile["kind"];
  mode: ResolvedProfileMode;
  profileRoot: string;
  manifestPath: string;
  configPath: string;
  stateDir: string;
  workspaceDir: string;
  basePort: number;
  configuredGatewayPort?: number;
  exists: boolean;
  managed: boolean;
  createdAt?: string;
  createdFrom?: string;
  adoptedFromLegacy?: string;
  warnings?: string[];
}): ResolvedProfile {
  return {
    ...params,
    effectiveGatewayPort:
      params.configuredGatewayPort && params.configuredGatewayPort > 0
        ? params.configuredGatewayPort
        : params.basePort,
    warnings: params.warnings ?? [],
  };
}

function buildResolvedManagedProfile(
  spec: ProfileSpec,
  profileRoot: string,
  configuredGatewayPort?: number,
): ResolvedProfile {
  return buildResolvedProfile({
    id: spec.id,
    kind: "managed",
    mode: spec.adoptedFromLegacy ? "adopted-legacy" : "managed-native",
    profileRoot,
    manifestPath: path.join(profileRoot, "profile.json"),
    configPath: resolveProfileComponentPath(profileRoot, spec.roots.config),
    stateDir: resolveProfileComponentPath(profileRoot, spec.roots.state),
    workspaceDir: resolveProfileComponentPath(profileRoot, spec.roots.workspace),
    basePort: spec.network.basePort,
    configuredGatewayPort,
    exists: true,
    managed: true,
    createdAt: spec.createdAt,
    createdFrom: spec.createdFrom,
    adoptedFromLegacy: spec.adoptedFromLegacy,
  });
}

export async function readManagedProfile(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile | null> {
  const profileRoot = resolveManagedProfileRoot(profileId, env, homedir);
  const manifestPath = path.join(profileRoot, "profile.json");
  const spec = await loadManagedProfileSpec(manifestPath);
  if (!spec) {
    return null;
  }
  try {
    const configuredGatewayPort = await readGatewayPortFromConfig(
      resolveProfileComponentPath(profileRoot, spec.roots.config),
    );
    return buildResolvedManagedProfile(spec, profileRoot, configuredGatewayPort);
  } catch (err) {
    return buildResolvedProfile({
      id: spec.id,
      kind: "managed",
      mode: spec.adoptedFromLegacy ? "adopted-legacy" : "managed-native",
      profileRoot,
      manifestPath,
      configPath: path.join(profileRoot, "config", CONFIG_FILENAME),
      stateDir: path.join(profileRoot, "state"),
      workspaceDir: path.join(profileRoot, "workspace"),
      basePort: spec.network.basePort,
      configuredGatewayPort: undefined,
      exists: true,
      managed: true,
      createdAt: spec.createdAt,
      createdFrom: spec.createdFrom,
      adoptedFromLegacy: spec.adoptedFromLegacy,
      warnings: [`Invalid profile manifest: ${String(err)}`],
    });
  }
}

export function readManagedProfileSync(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): ResolvedProfile | null {
  const profileRoot = resolveManagedProfileRoot(profileId, env, homedir);
  const manifestPath = path.join(profileRoot, "profile.json");
  const spec = loadManagedProfileSpecSync(manifestPath);
  if (!spec) {
    return null;
  }
  try {
    const configuredGatewayPort = readGatewayPortFromConfigSync(
      resolveProfileComponentPath(profileRoot, spec.roots.config),
    );
    return buildResolvedManagedProfile(spec, profileRoot, configuredGatewayPort);
  } catch (err) {
    return buildResolvedProfile({
      id: spec.id,
      kind: "managed",
      mode: spec.adoptedFromLegacy ? "adopted-legacy" : "managed-native",
      profileRoot,
      manifestPath,
      configPath: path.join(profileRoot, "config", CONFIG_FILENAME),
      stateDir: path.join(profileRoot, "state"),
      workspaceDir: path.join(profileRoot, "workspace"),
      basePort: spec.network.basePort,
      configuredGatewayPort: undefined,
      exists: true,
      managed: true,
      createdAt: spec.createdAt,
      createdFrom: spec.createdFrom,
      adoptedFromLegacy: spec.adoptedFromLegacy,
      warnings: [`Invalid profile manifest: ${String(err)}`],
    });
  }
}

function resolveLegacyNamedStateDir(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  return path.join(
    resolveRequiredHomeDir(env, homedir),
    `${DEFAULT_PROFILE_ROOT_BASENAME}-${profileId}`,
  );
}

function findLegacyExistingStateDir(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string | null {
  const id = normalizeProfileId(profileId);
  const effectiveHome = resolveRequiredHomeDir(env, homedir);
  const candidates =
    id === DEFAULT_PROFILE_ID
      ? LEGACY_STATE_DIRNAMES.map((name) => path.join(effectiveHome, name))
      : [resolveLegacyNamedStateDir(id, env, homedir)];
  return (
    candidates.find((candidate) => {
      try {
        if (!fs.existsSync(candidate)) {
          return false;
        }
        if (id !== DEFAULT_PROFILE_ID) {
          return true;
        }
        const entries = fs.readdirSync(candidate);
        return entries.some((entry) => entry !== PROFILE_SUBDIR);
      } catch {
        return false;
      }
    }) ?? null
  );
}

function resolveImplicitProfileRoot(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  const id = normalizeProfileId(profileId);
  return resolveManagedProfileRoot(id, env, homedir);
}

function resolveImplicitStateDir(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  const id = normalizeProfileId(profileId);
  return path.join(resolveManagedProfileRoot(id, env, homedir), "state");
}

function resolveImplicitConfigPath(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  const id = normalizeProfileId(profileId);
  return path.join(resolveManagedProfileRoot(id, env, homedir), "config", CONFIG_FILENAME);
}

function resolveImplicitWorkspaceDir(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): string {
  const id = normalizeProfileId(profileId);
  return path.join(resolveManagedProfileRoot(id, env, homedir), "workspace");
}

function resolveLegacyConfigPath(stateDir: string): string {
  return (
    LEGACY_CONFIG_FILENAMES.map((name) => path.join(stateDir, name)).find((candidate) => {
      try {
        return fs.existsSync(candidate);
      } catch {
        return false;
      }
    }) ?? path.join(stateDir, CONFIG_FILENAME)
  );
}

function resolveLegacyProfile(
  profileId: string,
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): ResolvedProfile {
  const id = normalizeProfileId(profileId);
  const configPath = resolveLegacyConfigPath(stateDir);
  const configuredGatewayPort = readGatewayPortFromConfigSync(configPath);
  return buildResolvedProfile({
    id,
    kind: "legacy",
    mode: "legacy-unmanaged",
    profileRoot: stateDir,
    manifestPath: path.join(resolveManagedProfileRoot(id, env, homedir), "profile.json"),
    configPath,
    stateDir,
    workspaceDir: path.join(stateDir, "workspace"),
    basePort: configuredGatewayPort ?? resolveDefaultBasePort(id),
    configuredGatewayPort,
    exists: true,
    managed: false,
  });
}

function resolveImplicitProfile(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): ResolvedProfile {
  const id = normalizeProfileId(profileId);
  const stateDir = resolveImplicitStateDir(id, env, homedir);
  return buildResolvedProfile({
    id,
    kind: "implicit",
    mode: id === DEFAULT_PROFILE_ID ? "implicit-default" : "implicit-managed",
    profileRoot: resolveImplicitProfileRoot(id, env, homedir),
    manifestPath: resolveManagedProfileManifestPath(id, env, homedir),
    configPath: resolveImplicitConfigPath(id, env, homedir),
    stateDir,
    workspaceDir: resolveImplicitWorkspaceDir(id, env, homedir),
    basePort: resolveDefaultBasePort(id),
    exists: false,
    managed: false,
  });
}

export async function resolveProfileSelection(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile> {
  const id = normalizeProfileId(profileId);
  const managed = await readManagedProfile(id, env, homedir);
  if (managed) {
    return managed;
  }
  const existingLegacy = findLegacyExistingStateDir(id, env, homedir);
  if (existingLegacy) {
    return resolveLegacyProfile(id, existingLegacy, env, homedir);
  }
  return resolveImplicitProfile(id, env, homedir);
}

export function resolveProfileSelectionSync(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): ResolvedProfile {
  const id = normalizeProfileId(profileId);
  const managed = readManagedProfileSync(id, env, homedir);
  if (managed) {
    return managed;
  }
  const existingLegacy = findLegacyExistingStateDir(id, env, homedir);
  if (existingLegacy) {
    return resolveLegacyProfile(id, existingLegacy, env, homedir);
  }
  return resolveImplicitProfile(id, env, homedir);
}

export async function resolveSelectedProfile(
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile | null> {
  const profileId = env.OPENCLAW_PROFILE?.trim();
  return profileId ? resolveProfileSelection(profileId, env, homedir) : null;
}

export function resolveSelectedProfileSync(
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): ResolvedProfile | null {
  const profileId = env.OPENCLAW_PROFILE?.trim();
  return profileId ? resolveProfileSelectionSync(profileId, env, homedir) : null;
}

export async function listProfiles(
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile[]> {
  const resolvedHome = resolveRequiredHomeDir(env, homedir);
  const managedRoot = resolveManagedProfilesHome(env, homedir);
  const results = new Map<string, ResolvedProfile>();

  try {
    const entries = await fsp.readdir(managedRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const profile = await readManagedProfile(entry.name, env, homedir);
      if (profile) {
        results.set(profile.id, profile);
      }
    }
  } catch {
    // No managed profile root yet.
  }

  const legacyEntries = await fsp.readdir(resolvedHome, { withFileTypes: true }).catch(() => []);
  for (const entry of legacyEntries) {
    if (!entry.isDirectory()) {
      continue;
    }
    let profileId: string | null = null;
    if (entry.name === DEFAULT_PROFILE_ROOT_BASENAME) {
      profileId = DEFAULT_PROFILE_ID;
    } else if (entry.name.startsWith(`${DEFAULT_PROFILE_ROOT_BASENAME}-`)) {
      profileId = normalizeProfileName(
        entry.name.slice(`${DEFAULT_PROFILE_ROOT_BASENAME}-`.length),
      );
    }
    if (!profileId || results.has(profileId)) {
      continue;
    }
    const legacyRoot = path.join(resolvedHome, entry.name);
    if (profileId === DEFAULT_PROFILE_ID) {
      try {
        const entries = await fsp.readdir(legacyRoot);
        if (!entries.some((item) => item !== PROFILE_SUBDIR)) {
          continue;
        }
      } catch {
        continue;
      }
    }
    results.set(profileId, resolveLegacyProfile(profileId, legacyRoot, env, homedir));
  }

  return [...results.values()].toSorted((a, b) => a.id.localeCompare(b.id));
}

export function createProfileSpec(params: {
  id: string;
  basePort: number;
  createdFrom?: string;
  createdAt?: string;
  adoptedFromLegacy?: string;
  roots?: Partial<ProfileSpec["roots"]>;
}): ProfileSpec {
  return {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    id: normalizeProfileId(params.id),
    roots: {
      config: params.roots?.config ?? path.join("config", CONFIG_FILENAME),
      state: params.roots?.state ?? "state",
      workspace: params.roots?.workspace ?? "workspace",
    },
    network: {
      basePort: params.basePort,
    },
    createdAt: params.createdAt ?? new Date().toISOString(),
    ...(params.createdFrom ? { createdFrom: params.createdFrom } : {}),
    ...(params.adoptedFromLegacy ? { adoptedFromLegacy: params.adoptedFromLegacy } : {}),
  };
}

export async function writeManagedProfileSpec(
  spec: ProfileSpec,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile> {
  const profileRoot = resolveManagedProfileRoot(spec.id, env, homedir);
  await fsp.mkdir(profileRoot, { recursive: true });
  await writeJsonAtomic(path.join(profileRoot, "profile.json"), spec, {
    mode: 0o600,
    trailingNewline: true,
    ensureDirMode: 0o700,
  });
  const resolved = buildResolvedManagedProfile(
    spec,
    profileRoot,
    readGatewayPortFromConfigSync(resolveProfileComponentPath(profileRoot, spec.roots.config)),
  );
  await fsp.mkdir(path.dirname(resolved.configPath), { recursive: true, mode: 0o700 });
  await fsp.mkdir(resolved.stateDir, { recursive: true, mode: 0o700 });
  await fsp.mkdir(resolved.workspaceDir, { recursive: true, mode: 0o700 });
  return resolved;
}

export async function importLegacyProfile(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile> {
  const existing = await readManagedProfile(profileId, env, homedir);
  if (existing) {
    return existing;
  }
  const selected = resolveProfileSelectionSync(profileId, env, homedir);
  if (selected.mode !== "legacy-unmanaged") {
    throw new Error(`Legacy profile not found: ${normalizeProfileId(profileId)}`);
  }
  const spec = createProfileSpec({
    id: selected.id,
    basePort: selected.effectiveGatewayPort,
    adoptedFromLegacy: selected.stateDir,
    roots: {
      config: selected.configPath,
      state: selected.stateDir,
      workspace: selected.workspaceDir,
    },
  });
  return writeManagedProfileSpec(spec, env, homedir);
}

export async function ensureManagedProfile(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<ResolvedProfile> {
  const existing = await readManagedProfile(profileId, env, homedir);
  if (existing) {
    return existing;
  }
  const selected = resolveProfileSelectionSync(profileId, env, homedir);
  if (selected.mode === "legacy-unmanaged") {
    return importLegacyProfile(profileId, env, homedir);
  }
  const basePort =
    selected.mode === "implicit-managed"
      ? await suggestProfileBasePort(env, homedir)
      : selected.effectiveGatewayPort;
  const spec = createProfileSpec({
    id: selected.id,
    basePort,
  });
  return writeManagedProfileSpec(spec, env, homedir);
}

export async function suggestProfileBasePort(
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = envHomedir(env),
): Promise<number> {
  const profiles = await listProfiles(env, homedir);
  const used = new Set<number>(profiles.map((profile) => profile.effectiveGatewayPort));
  let next = 19001;
  while (used.has(next)) {
    next += 20;
  }
  return next;
}
