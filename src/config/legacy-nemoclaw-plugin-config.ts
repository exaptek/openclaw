import { isRecord } from "../utils.js";

const PLUGIN_ENTRY_KEYS = new Set(["enabled", "hooks", "subagent", "config"]);

/**
 * Migrates mistaken `plugins.nemoclaw` (invalid top-level key under `plugins`) into
 * `plugins.entries.nemoclaw`, which is the supported shape for per-plugin settings.
 */
export function normalizeLegacyNemoclawPluginConfig<T>(raw: T): T {
  if (!isRecord(raw)) {
    return raw;
  }
  const plugins = raw.plugins;
  if (!isRecord(plugins)) {
    return raw;
  }
  if (!Object.prototype.hasOwnProperty.call(plugins, "nemoclaw")) {
    return raw;
  }

  const legacy = plugins.nemoclaw;
  const nextPlugins: Record<string, unknown> = { ...plugins };
  delete nextPlugins.nemoclaw;

  const entries: Record<string, unknown> = isRecord(nextPlugins.entries)
    ? { ...nextPlugins.entries }
    : {};
  const existing = isRecord(entries.nemoclaw) ? entries.nemoclaw : {};
  const merged: Record<string, unknown> = { ...existing };
  const configFromLegacy: Record<string, unknown> = isRecord(existing.config)
    ? { ...existing.config }
    : {};

  if (legacy !== null && typeof legacy === "object" && !Array.isArray(legacy)) {
    const leg = legacy as Record<string, unknown>;
    for (const [key, value] of Object.entries(leg)) {
      if (PLUGIN_ENTRY_KEYS.has(key)) {
        if (key === "config" && isRecord(value)) {
          Object.assign(configFromLegacy, value);
        } else {
          merged[key] = value;
        }
      } else {
        configFromLegacy[key] = value;
      }
    }
  }

  merged.config = configFromLegacy;
  entries.nemoclaw = merged;
  nextPlugins.entries = entries;

  return { ...raw, plugins: nextPlugins } as T;
}
