import { lookup as dnsLookupCb, type LookupAddress } from "node:dns";
import { lookup as dnsLookup, resolve4, resolve6 } from "node:dns/promises";
import type { Dispatcher } from "undici";
import { logError } from "../../logger.js";
import {
  extractEmbeddedIpv4FromIpv6,
  isBlockedSpecialUseIpv4Address,
  isBlockedSpecialUseIpv6Address,
  isCanonicalDottedDecimalIPv4,
  type Ipv4SpecialUseBlockOptions,
  isIpv4Address,
  isLegacyIpv4Literal,
  parseCanonicalIpAddress,
  parseLooseIpAddress,
} from "../../shared/net/ip.js";
import { normalizeHostname } from "./hostname.js";
import { hasEnvHttpProxyConfigured, hasProxyEnvConfigured } from "./proxy-env.js";
import { loadUndiciRuntimeDeps } from "./undici-runtime.js";

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

export class SsrFBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrFBlockedError";
  }
}

export type LookupFn = typeof dnsLookup;

export type SsrFPolicy = {
  allowPrivateNetwork?: boolean;
  dangerouslyAllowPrivateNetwork?: boolean;
  allowRfc2544BenchmarkRange?: boolean;
  allowedHostnames?: string[];
  hostnameAllowlist?: string[];
};

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
]);

function normalizeHostnameSet(values?: string[]): Set<string> {
  if (!values || values.length === 0) {
    return new Set<string>();
  }
  return new Set(values.map((value) => normalizeHostname(value)).filter(Boolean));
}

function normalizeHostnameAllowlist(values?: string[]): string[] {
  if (!values || values.length === 0) {
    return [];
  }
  return Array.from(
    new Set(
      values
        .map((value) => normalizeHostname(value))
        .filter((value) => value !== "*" && value !== "*." && value.length > 0),
    ),
  );
}

export function isPrivateNetworkAllowedByPolicy(policy?: SsrFPolicy): boolean {
  return policy?.dangerouslyAllowPrivateNetwork === true || policy?.allowPrivateNetwork === true;
}

function shouldSkipPrivateNetworkChecks(hostname: string, policy?: SsrFPolicy): boolean {
  return (
    isPrivateNetworkAllowedByPolicy(policy) ||
    normalizeHostnameSet(policy?.allowedHostnames).has(hostname)
  );
}

function resolveIpv4SpecialUseBlockOptions(policy?: SsrFPolicy): Ipv4SpecialUseBlockOptions {
  return {
    allowRfc2544BenchmarkRange: policy?.allowRfc2544BenchmarkRange === true,
  };
}

function isHostnameAllowedByPattern(hostname: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    if (!suffix || hostname === suffix) {
      return false;
    }
    return hostname.endsWith(`.${suffix}`);
  }
  return hostname === pattern;
}

function matchesHostnameAllowlist(hostname: string, allowlist: string[]): boolean {
  if (allowlist.length === 0) {
    return true;
  }
  return allowlist.some((pattern) => isHostnameAllowedByPattern(hostname, pattern));
}

function looksLikeUnsupportedIpv4Literal(address: string): boolean {
  const parts = address.split(".");
  if (parts.length === 0 || parts.length > 4) {
    return false;
  }
  if (parts.some((part) => part.length === 0)) {
    return true;
  }
  // Tighten only "ipv4-ish" literals (numbers + optional 0x prefix). Hostnames like
  // "example.com" must stay in hostname policy handling and not be treated as malformed IPs.
  return parts.every((part) => /^[0-9]+$/.test(part) || /^0x/i.test(part));
}

// Returns true for private/internal and special-use non-global addresses.
export function isPrivateIpAddress(address: string, policy?: SsrFPolicy): boolean {
  let normalized = address.trim().toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }
  if (!normalized) {
    return false;
  }
  const blockOptions = resolveIpv4SpecialUseBlockOptions(policy);

  const strictIp = parseCanonicalIpAddress(normalized);
  if (strictIp) {
    if (isIpv4Address(strictIp)) {
      return isBlockedSpecialUseIpv4Address(strictIp, blockOptions);
    }
    if (isBlockedSpecialUseIpv6Address(strictIp)) {
      return true;
    }
    const embeddedIpv4 = extractEmbeddedIpv4FromIpv6(strictIp);
    if (embeddedIpv4) {
      return isBlockedSpecialUseIpv4Address(embeddedIpv4, blockOptions);
    }
    return false;
  }

  // Security-critical parse failures should fail closed for any malformed IPv6 literal.
  if (normalized.includes(":") && !parseLooseIpAddress(normalized)) {
    return true;
  }

  if (!isCanonicalDottedDecimalIPv4(normalized) && isLegacyIpv4Literal(normalized)) {
    return true;
  }
  if (looksLikeUnsupportedIpv4Literal(normalized)) {
    return true;
  }
  return false;
}

export function isBlockedHostname(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return false;
  }
  return isBlockedHostnameNormalized(normalized);
}

function isBlockedHostnameNormalized(normalized: string): boolean {
  if (BLOCKED_HOSTNAMES.has(normalized)) {
    return true;
  }
  return (
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal")
  );
}

export function isBlockedHostnameOrIp(hostname: string, policy?: SsrFPolicy): boolean {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return false;
  }
  return isBlockedHostnameNormalized(normalized) || isPrivateIpAddress(normalized, policy);
}

const BLOCKED_HOST_OR_IP_MESSAGE = "Blocked hostname or private/internal/special-use IP address";
const BLOCKED_RESOLVED_IP_MESSAGE = "Blocked: resolves to private/internal/special-use IP address";

function assertAllowedHostOrIpOrThrow(hostnameOrIp: string, policy?: SsrFPolicy): void {
  if (isBlockedHostnameOrIp(hostnameOrIp, policy)) {
    throw new SsrFBlockedError(BLOCKED_HOST_OR_IP_MESSAGE);
  }
}

function assertAllowedResolvedAddressesOrThrow(
  results: readonly LookupAddress[],
  policy?: SsrFPolicy,
): void {
  for (const entry of results) {
    // Reuse the exact same host/IP classifier as the pre-DNS check to avoid drift.
    if (isBlockedHostnameOrIp(entry.address, policy)) {
      throw new SsrFBlockedError(BLOCKED_RESOLVED_IP_MESSAGE);
    }
  }
}

export function createPinnedLookup(params: {
  hostname: string;
  addresses: string[];
  fallback?: typeof dnsLookupCb;
}): typeof dnsLookupCb {
  const normalizedHost = normalizeHostname(params.hostname);
  if (params.addresses.length === 0) {
    throw new Error(`Pinned lookup requires at least one address for ${params.hostname}`);
  }
  const fallback = params.fallback ?? dnsLookupCb;
  const fallbackLookup = fallback as unknown as (
    hostname: string,
    callback: LookupCallback,
  ) => void;
  const fallbackWithOptions = fallback as unknown as (
    hostname: string,
    options: unknown,
    callback: LookupCallback,
  ) => void;
  const records = params.addresses.map((address) => ({
    address,
    family: address.includes(":") ? 6 : 4,
  }));
  let index = 0;

  return ((host: string, options?: unknown, callback?: unknown) => {
    const cb: LookupCallback =
      typeof options === "function" ? (options as LookupCallback) : (callback as LookupCallback);
    if (!cb) {
      return;
    }
    const normalized = normalizeHostname(host);
    if (!normalized || normalized !== normalizedHost) {
      if (typeof options === "function" || options === undefined) {
        return fallbackLookup(host, cb);
      }
      return fallbackWithOptions(host, options, cb);
    }

    const opts =
      typeof options === "object" && options !== null
        ? (options as { all?: boolean; family?: number })
        : {};
    const requestedFamily =
      typeof options === "number" ? options : typeof opts.family === "number" ? opts.family : 0;
    const candidates =
      requestedFamily === 4 || requestedFamily === 6
        ? records.filter((entry) => entry.family === requestedFamily)
        : records;
    const usable = candidates.length > 0 ? candidates : records;
    if (opts.all) {
      cb(null, usable as LookupAddress[]);
      return;
    }
    const chosen = usable[index % usable.length];
    index += 1;
    cb(null, chosen.address, chosen.family);
  }) as typeof dnsLookupCb;
}

export type PinnedHostname = {
  hostname: string;
  addresses: string[];
  lookup: typeof dnsLookupCb;
};

export type PinnedHostnameOverride = {
  hostname: string;
  addresses: string[];
};

export type PinnedDispatcherPolicy =
  | {
      mode: "direct";
      connect?: Record<string, unknown>;
      pinnedHostname?: PinnedHostnameOverride;
    }
  | {
      mode: "env-proxy";
      connect?: Record<string, unknown>;
      proxyTls?: Record<string, unknown>;
      pinnedHostname?: PinnedHostnameOverride;
    }
  | {
      mode: "explicit-proxy";
      proxyUrl: string;
      proxyTls?: Record<string, unknown>;
      pinnedHostname?: PinnedHostnameOverride;
    };

/** Transient resolver failures in k8s / c-ares; retry before surfacing to web_fetch. */
const RETRYABLE_DNS_CODES = new Set(["EAI_AGAIN", "ETIMEDOUT", "EBUSY"]);

function dnsEnvSnapshot(): string {
  return [
    `hasProxyEnv=${hasProxyEnvConfigured()}`,
    `hasHttpsProxyEnv=${hasEnvHttpProxyConfigured("https")}`,
    `NODE_USE_ENV_PROXY=${process.env.NODE_USE_ENV_PROXY ?? "(unset)"}`,
  ].join(" ");
}

function logDnsSsrF(message: string): void {
  // Use logError so lines reach the same nohup/stderr capture as `[tools]` (logWarn is often filtered).
  logError(`dns:ssrf: ${message}`);
}

function formatErrBrief(err: unknown): string {
  if (err instanceof Error) {
    const errno = err as NodeJS.ErrnoException;
    const code = errno.code ? ` code=${errno.code}` : "";
    return `${err.name}: ${err.message}${code}`;
  }
  return String(err);
}

function summarizeAddresses(records: readonly LookupAddress[], max = 12): string {
  if (records.length === 0) {
    return "(none)";
  }
  const slice = records.slice(0, max);
  const parts = slice.map((r) => `${r.address}@${r.family}`);
  const more = records.length > max ? ` +${records.length - max} more` : "";
  return `${parts.join(", ")}${more}`;
}

/** Google public DNS JSON API (HTTPS). Used when UDP/TCP DNS from the pod is blocked or flaky. */
const GOOGLE_DNS_JSON_BASE = "https://dns.google/resolve";

type GoogleDnsJsonResponse = {
  Status: number;
  Answer?: Array<{ type: number; data: string }>;
};

function parseGoogleDnsJsonRecords(body: GoogleDnsJsonResponse): LookupAddress[] {
  if (body.Status !== 0 || !body.Answer) {
    return [];
  }
  const out: LookupAddress[] = [];
  for (const ans of body.Answer) {
    if (ans.type === 1) {
      out.push({ address: ans.data, family: 4 as const });
    } else if (ans.type === 28) {
      out.push({ address: ans.data, family: 6 as const });
    }
  }
  return out;
}

/**
 * Resolve via Google DNS JSON over HTTPS (CONNECT through egress proxy in sandboxes).
 * Avoids local UDP/TCP DNS when CoreDNS/getaddrinfo flakes or external 53 is blocked.
 */
async function resolveHostnameViaGoogleDnsJson(hostname: string): Promise<LookupAddress[]> {
  const q = encodeURIComponent(hostname);
  const fetchImpl = globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available for DNS-over-HTTPS fallback");
  }
  // Gateway and other entrypoints do not always install EnvHttpProxyAgent as the global
  // undici dispatcher; OpenShell sandboxes require CONNECT via HTTP(S)_PROXY for outbound HTTPS.
  const { EnvHttpProxyAgent } = loadUndiciRuntimeDeps();
  const dispatcher = hasEnvHttpProxyConfigured("https") ? new EnvHttpProxyAgent() : undefined;
  logDnsSsrF(
    `doh: start host=${hostname} dispatcher=${dispatcher ? "EnvHttpProxyAgent" : "default"} ${dnsEnvSnapshot()}`,
  );
  const init: RequestInit & { dispatcher?: Dispatcher } = dispatcher ? { dispatcher } : {};
  try {
    const [aResp, aaaaResp] = await Promise.all([
      fetchImpl(`${GOOGLE_DNS_JSON_BASE}?name=${q}&type=A`, init),
      fetchImpl(`${GOOGLE_DNS_JSON_BASE}?name=${q}&type=AAAA`, init),
    ]);
    logDnsSsrF(
      `doh: http status A=${aResp.status} AAAA=${aaaaResp.status} okA=${aResp.ok} okAAAA=${aaaaResp.ok} host=${hostname}`,
    );
    if (!aResp.ok && !aaaaResp.ok) {
      throw new Error(
        `Google DNS JSON HTTP ${aResp.status} / ${aaaaResp.status} (allowlist dns.google for openclaw/node)`,
      );
    }
    const [aJson, aaaaJson] = (await Promise.all([aResp.json(), aaaaResp.json()])) as [
      GoogleDnsJsonResponse,
      GoogleDnsJsonResponse,
    ];
    const merged = [...parseGoogleDnsJsonRecords(aJson), ...parseGoogleDnsJsonRecords(aaaaJson)];
    if (merged.length === 0) {
      logDnsSsrF(
        `doh: empty Answer after parse host=${hostname} jsonStatus A=${aJson.Status} AAAA=${aaaaJson.Status}`,
      );
      throw new Error(`Unable to resolve hostname: ${hostname}`);
    }
    logDnsSsrF(`doh: ok host=${hostname} records=${summarizeAddresses(merged)}`);
    return merged;
  } catch (e) {
    logDnsSsrF(`doh: failed host=${hostname} err=${formatErrBrief(e)}`);
    throw e;
  } finally {
    await closeDispatcher(dispatcher ?? null);
  }
}

/** Fewer attempts so we reach DNS-over-HTTPS quickly when getaddrinfo stalls per try. */
const LOOKUP_MAX_ATTEMPTS = 3;
const PROTOCOL_RESOLVE_MAX_ATTEMPTS = 2;

function backoffMsForAttempt(attempt: number): number {
  return Math.min(1000, 50 * 2 ** (attempt - 1));
}

/** getaddrinfo can block a long time before returning EAI_AGAIN; cap per try so DoH runs. */
const LOOKUP_PER_ATTEMPT_TIMEOUT_MS = 1500;

function lookupWithTimeout(
  lookupFn: LookupFn,
  hostname: string,
  opts: { all: true },
): Promise<LookupAddress[]> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      logDnsSsrF(
        `lookup: timeout after ${LOOKUP_PER_ATTEMPT_TIMEOUT_MS}ms host=${hostname} (synthetic ETIMEDOUT)`,
      );
      reject(
        Object.assign(new Error(`dns.lookup timed out after ${LOOKUP_PER_ATTEMPT_TIMEOUT_MS}ms`), {
          code: "ETIMEDOUT",
        }),
      );
    }, LOOKUP_PER_ATTEMPT_TIMEOUT_MS);
    void lookupFn(hostname, opts)
      .then((r) => {
        clearTimeout(timer);
        resolve(r);
      })
      .catch((e) => {
        clearTimeout(timer);
        reject(e);
      });
  });
}

async function lookupDnsWithRetry(
  lookupFn: LookupFn,
  hostname: string,
  opts: { all: true },
  maxAttempts = LOOKUP_MAX_ATTEMPTS,
): Promise<LookupAddress[]> {
  logDnsSsrF(`lookup: dns.lookup with retry start host=${hostname} maxAttempts=${maxAttempts}`);
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const results = await lookupWithTimeout(lookupFn, hostname, opts);
      if (!Array.isArray(results)) {
        throw new Error(`Unexpected DNS lookup result shape for ${hostname}`);
      }
      if (results.length === 0) {
        throw new Error(`Unable to resolve hostname: ${hostname}`);
      }
      logDnsSsrF(
        `lookup: dns.lookup ok host=${hostname} attempt=${attempt}/${maxAttempts} records=${summarizeAddresses(results)}`,
      );
      return results;
    } catch (e) {
      lastErr = e;
      const code = (e as NodeJS.ErrnoException)?.code;
      logDnsSsrF(
        `lookup: dns.lookup fail host=${hostname} attempt=${attempt}/${maxAttempts} err=${formatErrBrief(e)} retryable=${code ? RETRYABLE_DNS_CODES.has(code) : false}`,
      );
      if (code && RETRYABLE_DNS_CODES.has(code) && attempt < maxAttempts) {
        const delay = backoffMsForAttempt(attempt);
        logDnsSsrF(`lookup: backoff ${delay}ms before retry host=${hostname}`);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw e;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

function isBenignDnsMiss(code: string | undefined): boolean {
  return code === "ENOTFOUND" || code === "ENODATA";
}

/**
 * When `dns.lookup` (getaddrinfo) flakes in constrained namespaces, direct A/AAAA
 * queries often still succeed. Merge IPv4 first to match dedupeAndPreferIpv4.
 */
async function resolveHostnameViaDnsProtocol(hostname: string): Promise<LookupAddress[]> {
  logDnsSsrF(
    `proto: resolve4/resolve6 start host=${hostname} maxAttempts=${PROTOCOL_RESOLVE_MAX_ATTEMPTS}`,
  );
  let lastErr: unknown;
  for (let attempt = 1; attempt <= PROTOCOL_RESOLVE_MAX_ATTEMPTS; attempt++) {
    try {
      const [v4, v6] = await Promise.all([
        resolve4(hostname).catch((e: NodeJS.ErrnoException) => {
          if (isBenignDnsMiss(e?.code)) {
            return [] as string[];
          }
          throw e;
        }),
        resolve6(hostname).catch((e: NodeJS.ErrnoException) => {
          if (isBenignDnsMiss(e?.code)) {
            return [] as string[];
          }
          throw e;
        }),
      ]);
      const results: LookupAddress[] = [
        ...v4.map((address) => ({ address, family: 4 as const })),
        ...v6.map((address) => ({ address, family: 6 as const })),
      ];
      if (results.length > 0) {
        logDnsSsrF(
          `proto: ok host=${hostname} attempt=${attempt} records=${summarizeAddresses(results)}`,
        );
        return results;
      }
      throw new Error(`Unable to resolve hostname: ${hostname}`);
    } catch (e) {
      lastErr = e;
      const code = (e as NodeJS.ErrnoException)?.code;
      logDnsSsrF(
        `proto: fail host=${hostname} attempt=${attempt}/${PROTOCOL_RESOLVE_MAX_ATTEMPTS} err=${formatErrBrief(e)}`,
      );
      if (code && RETRYABLE_DNS_CODES.has(code) && attempt < PROTOCOL_RESOLVE_MAX_ATTEMPTS) {
        const delay = backoffMsForAttempt(attempt);
        logDnsSsrF(`proto: backoff ${delay}ms host=${hostname}`);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw e;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

function formatDnsFallbackDetail(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

async function lookupDnsWithRetryAndProtocolFallback(
  lookupFn: LookupFn,
  hostname: string,
  opts: { all: true },
): Promise<LookupAddress[]> {
  logDnsSsrF(`chain: start host=${hostname} ${dnsEnvSnapshot()}`);
  let dohPreflightAttempted = false;
  let dohPreflightErr: unknown;

  // When HTTP(S)_PROXY is set (OpenShell sandboxes), skip flaky local dns.lookup first:
  // c-ares + ndots/search paths often return EAI_AGAIN while CONNECT to dns.google works.
  if (hasProxyEnvConfigured()) {
    logDnsSsrF(`chain: proxy env set — trying DoH preflight before dns.lookup host=${hostname}`);
    try {
      const out = await resolveHostnameViaGoogleDnsJson(hostname);
      logDnsSsrF(`chain: exit via DoH preflight host=${hostname}`);
      return out;
    } catch (doh) {
      dohPreflightAttempted = true;
      dohPreflightErr = doh;
      logDnsSsrF(
        `chain: DoH preflight failed host=${hostname} err=${formatErrBrief(doh)} — falling back to dns.lookup`,
      );
    }
  } else {
    logDnsSsrF(`chain: no proxy env — skipping DoH preflight host=${hostname}`);
  }

  try {
    const out = await lookupDnsWithRetry(lookupFn, hostname, opts);
    logDnsSsrF(`chain: exit via dns.lookup host=${hostname}`);
    return out;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    logDnsSsrF(
      `chain: dns.lookup threw host=${hostname} code=${String(code)} retryable=${code ? RETRYABLE_DNS_CODES.has(code) : false} err=${formatErrBrief(e)} dohPreflightAttempted=${dohPreflightAttempted}`,
    );
    if (code && RETRYABLE_DNS_CODES.has(code)) {
      if (!dohPreflightAttempted) {
        // Prefer DNS-over-HTTPS: UDP DNS to resolvers often stalls while DoH via proxy works.
        logDnsSsrF(`chain: retry path — DoH then proto (preflight was skipped) host=${hostname}`);
        let dohErr: unknown;
        try {
          const out = await resolveHostnameViaGoogleDnsJson(hostname);
          logDnsSsrF(`chain: exit via DoH after lookup fail host=${hostname}`);
          return out;
        } catch (doh) {
          dohErr = doh;
          logDnsSsrF(
            `chain: DoH after lookup fail failed host=${hostname} err=${formatErrBrief(doh)}`,
          );
          let protoErr: unknown;
          try {
            const out = await resolveHostnameViaDnsProtocol(hostname);
            logDnsSsrF(`chain: exit via proto after lookup+DoH fail host=${hostname}`);
            return out;
          } catch (proto) {
            protoErr = proto;
            logDnsSsrF(
              `chain: aggregate failure (lookup+DoH+proto) host=${hostname} proto=${formatErrBrief(proto)}`,
            );
            const chain: Error[] = [];
            if (e instanceof Error) {
              chain.push(e);
            }
            if (dohErr instanceof Error) {
              chain.push(dohErr);
            }
            if (proto instanceof Error) {
              chain.push(proto);
            }
            if (chain.length === 0) {
              chain.push(new Error("DNS fallback failed with non-Error throws"));
            }
            // oxlint-disable-next-line preserve-caught-error -- intentional aggregate cause for multi-stage DNS fallback
            throw new Error(
              `DNS resolution failed for ${hostname} after local dns.lookup (${String(code)}). ` +
                `DNS-over-HTTPS: ${formatDnsFallbackDetail(dohErr)}; protocol resolve4/6: ${formatDnsFallbackDetail(protoErr)}`,
              { cause: new AggregateError(chain, "DNS resolution fallbacks failed") },
            );
          }
        }
      }

      logDnsSsrF(`chain: retry path — proto only (DoH preflight already failed) host=${hostname}`);
      let protoErr: unknown;
      try {
        const out = await resolveHostnameViaDnsProtocol(hostname);
        logDnsSsrF(`chain: exit via proto after preflight-DoH-fail host=${hostname}`);
        return out;
      } catch (proto) {
        protoErr = proto;
        logDnsSsrF(
          `chain: aggregate failure (lookup+preflight-DoH+proto) host=${hostname} proto=${formatErrBrief(proto)}`,
        );
        const chain: Error[] = [];
        if (e instanceof Error) {
          chain.push(e);
        }
        if (dohPreflightErr instanceof Error) {
          chain.push(dohPreflightErr);
        }
        if (proto instanceof Error) {
          chain.push(proto);
        }
        if (chain.length === 0) {
          chain.push(new Error("DNS fallback failed with non-Error throws"));
        }
        // oxlint-disable-next-line preserve-caught-error -- intentional aggregate cause for multi-stage DNS fallback
        throw new Error(
          `DNS resolution failed for ${hostname} after local dns.lookup (${String(code)}). ` +
            `DNS-over-HTTPS (preflight): ${formatDnsFallbackDetail(dohPreflightErr)}; protocol resolve4/6: ${formatDnsFallbackDetail(protoErr)}`,
          { cause: new AggregateError(chain, "DNS resolution fallbacks failed") },
        );
      }
    }
    logDnsSsrF(`chain: non-retryable or missing code — rethrow host=${hostname}`);
    throw e;
  }
}

function dedupeAndPreferIpv4(results: readonly LookupAddress[]): string[] {
  const seen = new Set<string>();
  const ipv4: string[] = [];
  const otherFamilies: string[] = [];
  for (const entry of results) {
    if (seen.has(entry.address)) {
      continue;
    }
    seen.add(entry.address);
    if (entry.family === 4) {
      ipv4.push(entry.address);
      continue;
    }
    otherFamilies.push(entry.address);
  }
  return [...ipv4, ...otherFamilies];
}

export async function resolvePinnedHostnameWithPolicy(
  hostname: string,
  params: { lookupFn?: LookupFn; policy?: SsrFPolicy } = {},
): Promise<PinnedHostname> {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    throw new Error("Invalid hostname");
  }

  const hostnameAllowlist = normalizeHostnameAllowlist(params.policy?.hostnameAllowlist);
  const skipPrivateNetworkChecks = shouldSkipPrivateNetworkChecks(normalized, params.policy);
  const allowlistLen = hostnameAllowlist.length;
  logDnsSsrF(
    `pin: resolvePinnedHostnameWithPolicy input=${hostname} normalized=${normalized} allowlistPatterns=${allowlistLen} skipPrivate=${skipPrivateNetworkChecks} ${dnsEnvSnapshot()}`,
  );

  if (!matchesHostnameAllowlist(normalized, hostnameAllowlist)) {
    logDnsSsrF(`pin: blocked by hostname allowlist host=${normalized}`);
    throw new SsrFBlockedError(`Blocked hostname (not in allowlist): ${hostname}`);
  }

  if (!skipPrivateNetworkChecks) {
    // Phase 1: fail fast for literal hosts/IPs before any DNS lookup side-effects.
    assertAllowedHostOrIpOrThrow(normalized, params.policy);
  }

  const lookupFn = params.lookupFn ?? dnsLookup;
  const results = await lookupDnsWithRetryAndProtocolFallback(lookupFn, normalized, { all: true });
  if (results.length === 0) {
    logDnsSsrF(`pin: zero DNS results host=${normalized}`);
    throw new Error(`Unable to resolve hostname: ${hostname}`);
  }

  if (!skipPrivateNetworkChecks) {
    // Phase 2: re-check DNS answers so public hostnames cannot pivot to private targets.
    assertAllowedResolvedAddressesOrThrow(results, params.policy);
  }

  // Prefer addresses returned as IPv4 by DNS family metadata before other
  // families so Happy Eyeballs and pinned round-robin both attempt IPv4 first.
  const addresses = dedupeAndPreferIpv4(results);
  if (addresses.length === 0) {
    logDnsSsrF(`pin: dedupe left zero addresses host=${normalized}`);
    throw new Error(`Unable to resolve hostname: ${hostname}`);
  }

  logDnsSsrF(
    `pin: success host=${normalized} addresses=${summarizeAddresses(
      addresses.map((a) => ({ address: a, family: a.includes(":") ? 6 : 4 })),
    )}`,
  );
  return {
    hostname: normalized,
    addresses,
    lookup: createPinnedLookup({ hostname: normalized, addresses }),
  };
}

export async function resolvePinnedHostname(
  hostname: string,
  lookupFn: LookupFn = dnsLookup,
): Promise<PinnedHostname> {
  return await resolvePinnedHostnameWithPolicy(hostname, { lookupFn });
}

function withPinnedLookup(
  lookup: PinnedHostname["lookup"],
  connect?: Record<string, unknown>,
): Record<string, unknown> {
  return connect ? { ...connect, lookup } : { lookup };
}

function resolvePinnedDispatcherLookup(
  pinned: PinnedHostname,
  override?: PinnedHostnameOverride,
  policy?: SsrFPolicy,
): PinnedHostname["lookup"] {
  if (!override) {
    return pinned.lookup;
  }
  const normalizedOverrideHost = normalizeHostname(override.hostname);
  if (!normalizedOverrideHost || normalizedOverrideHost !== pinned.hostname) {
    throw new Error(
      `Pinned dispatcher override hostname mismatch: expected ${pinned.hostname}, got ${override.hostname}`,
    );
  }
  const records = override.addresses.map((address) => ({
    address,
    family: address.includes(":") ? 6 : 4,
  }));
  if (!shouldSkipPrivateNetworkChecks(pinned.hostname, policy)) {
    assertAllowedResolvedAddressesOrThrow(records, policy);
  }
  return createPinnedLookup({
    hostname: pinned.hostname,
    addresses: [...override.addresses],
    fallback: pinned.lookup,
  });
}

export function createPinnedDispatcher(
  pinned: PinnedHostname,
  policy?: PinnedDispatcherPolicy,
  ssrfPolicy?: SsrFPolicy,
): Dispatcher {
  const { Agent, EnvHttpProxyAgent, ProxyAgent } = loadUndiciRuntimeDeps();
  const lookup = resolvePinnedDispatcherLookup(pinned, policy?.pinnedHostname, ssrfPolicy);

  if (!policy || policy.mode === "direct") {
    return new Agent({
      connect: withPinnedLookup(lookup, policy?.connect),
    });
  }

  if (policy.mode === "env-proxy") {
    return new EnvHttpProxyAgent({
      connect: withPinnedLookup(lookup, policy.connect),
      ...(policy.proxyTls ? { proxyTls: { ...policy.proxyTls } } : {}),
    });
  }

  const proxyUrl = policy.proxyUrl.trim();
  const requestTls = withPinnedLookup(lookup, policy.proxyTls);
  if (!requestTls) {
    return new ProxyAgent(proxyUrl);
  }
  return new ProxyAgent({
    uri: proxyUrl,
    // `PinnedDispatcherPolicy.proxyTls` historically carried target-hop
    // transport hints for explicit proxies. Translate that to undici's
    // `requestTls` so HTTPS proxy tunnels keep the pinned DNS lookup.
    requestTls,
  });
}

export async function closeDispatcher(dispatcher?: Dispatcher | null): Promise<void> {
  if (!dispatcher) {
    return;
  }
  const candidate = dispatcher as { close?: () => Promise<void> | void; destroy?: () => void };
  try {
    if (typeof candidate.close === "function") {
      await candidate.close();
      return;
    }
    if (typeof candidate.destroy === "function") {
      candidate.destroy();
    }
  } catch {
    // ignore dispatcher cleanup errors
  }
}

export async function assertPublicHostname(
  hostname: string,
  lookupFn: LookupFn = dnsLookup,
): Promise<void> {
  await resolvePinnedHostname(hostname, lookupFn);
}
