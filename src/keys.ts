// @enfinitos/sdk-auditor — verification key source.
//
// The auditor SDK gets verification keys from one of two places:
//
//   1. **Platform endpoint** (`/v1/runtime-keys`). The default. The
//      SDK fetches once at construction, caches in-memory, and
//      records the snapshot ID + issuance timestamp into every audit
//      report so the verification is reproducible.
//
//   2. **Local file.** The auditor supplies a JSON array of
//      VerificationKey objects (typically pinned at a specific
//      moment in time so a months-later re-audit uses exactly the
//      same key set). This is the path regulators use; they do not
//      want to depend on a live HTTP endpoint years after the fact.
//
// The cache is **deliberately not time-bounded**. A long-running
// auditor process working on a months-old proof pack does NOT want
// the SDK to refresh the key directory mid-audit — that would change
// the verification outcome of subsequent records inside the same
// pack, which would be a categorical violation of "an audit run is
// reproducible". To rotate the cache, the caller constructs a new
// EnfinitOSAuditor.

import {
  AuditorError,
  asAuditorError,
  type AuditorErrorCode,
} from "./errors.js";
import type {
  RuntimeKeysResponse,
  SignatureAlgorithm,
  VerificationKey,
} from "./types.js";

// ─────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────

export type VerificationKeySourceKind = "platform" | "local";

export type KeyDirectorySnapshot = {
  source: VerificationKeySourceKind;
  snapshotId: string | null;
  issuedAt: string | null;
  keys: VerificationKey[];
};

export type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

export type KeyDirectoryOptions = {
  source: VerificationKeySourceKind;
  /** Endpoint URL — only consulted when source === "platform". */
  platformKeysUrl?: string;
  /** Locally-supplied keys — only consulted when source === "local". */
  localKeys?: VerificationKey[];
  /** Injectable fetch — for tests. */
  httpFetch?: FetchLike;
};

const DEFAULT_PLATFORM_KEYS_URL = "https://api.enfinitos.com/v1/runtime-keys";

// ─────────────────────────────────────────────────────────────────────
// KeyDirectory — the in-process cache the SDK consults per record
// ─────────────────────────────────────────────────────────────────────

/**
 * KeyDirectory — minimal index over a set of VerificationKey objects.
 *
 * Once constructed it is immutable: lookups are constant-time, and a
 * caller that wants new keys constructs a fresh KeyDirectory.
 *
 * Lookups apply validity-window + revocation checks at the call site,
 * not at construction, because the same key may be valid for one
 * record's `issuedAt` and invalid for another's.
 */
export class KeyDirectory {
  private readonly index: Map<string, VerificationKey>;

  constructor(public readonly snapshot: KeyDirectorySnapshot) {
    const index = new Map<string, VerificationKey>();
    for (const k of snapshot.keys) {
      if (index.has(k.keyId)) {
        // Duplicate keyId in the directory is a platform bug — we
        // reject the snapshot rather than silently using the last
        // one written, because the wrong choice would invalidate the
        // audit.
        throw new AuditorError({
          code: "KEYS_MALFORMED",
          message: `duplicate keyId in key directory: ${k.keyId}`,
        });
      }
      index.set(k.keyId, k);
    }
    this.index = index;
  }

  /**
   * Look up a key by ID, returning either the key or a structured
   * "miss" reason. Returning a discriminated union here (rather than
   * throwing on miss) is deliberate — an unknown keyId is an audit
   * failure, not an operational failure, and the caller wants it as
   * an AuditStep status not an exception.
   */
  lookup(keyId: string, issuedAtIso: string): KeyLookupResult {
    const key = this.index.get(keyId);
    if (!key) {
      return { kind: "miss", reason: "UNKNOWN_KEY_ID" };
    }
    const issuedAt = Date.parse(issuedAtIso);
    if (!Number.isFinite(issuedAt)) {
      // Caller's record carries an unparseable issuedAt. This is a
      // pack-level error, not a key-level one — but reporting it as
      // an UNKNOWN_KEY_ID would be wrong (the key is fine), and
      // reporting it as a key-window violation is the least-wrong
      // option. The signature step will produce a more specific
      // failure too.
      return {
        kind: "miss",
        reason: "KEY_OUTSIDE_VALIDITY_WINDOW",
      };
    }
    const notBefore = Date.parse(key.notBefore);
    if (Number.isFinite(notBefore) && issuedAt < notBefore) {
      return { kind: "miss", reason: "KEY_OUTSIDE_VALIDITY_WINDOW" };
    }
    if (key.notAfter !== null) {
      const notAfter = Date.parse(key.notAfter);
      if (Number.isFinite(notAfter) && issuedAt > notAfter) {
        return { kind: "miss", reason: "KEY_OUTSIDE_VALIDITY_WINDOW" };
      }
    }
    if (key.revokedAt !== null) {
      const revokedAt = Date.parse(key.revokedAt);
      if (Number.isFinite(revokedAt) && issuedAt > revokedAt) {
        return { kind: "miss", reason: "KEY_REVOKED_BEFORE_ISSUANCE" };
      }
    }
    return { kind: "hit", key };
  }

  /** Number of keys in the directory. */
  size(): number {
    return this.index.size;
  }

  /** Stable list of keyIds — used for AuditReport.keysSnapshot. */
  keyIds(): string[] {
    return [...this.index.keys()].sort();
  }
}

export type KeyLookupResult =
  | { kind: "hit"; key: VerificationKey }
  | {
      kind: "miss";
      reason: "UNKNOWN_KEY_ID" | "KEY_OUTSIDE_VALIDITY_WINDOW" | "KEY_REVOKED_BEFORE_ISSUANCE";
    };

// ─────────────────────────────────────────────────────────────────────
// Loading: from local or from platform
// ─────────────────────────────────────────────────────────────────────

/**
 * Load a KeyDirectory from the options. Validates the keys' shape;
 * a malformed key set is rejected as `KEYS_MALFORMED`.
 *
 * Throws AuditorError on:
 *   - INVALID_INPUT:    options inconsistent
 *   - KEYS_UNAVAILABLE: fetch failure for platform source
 *   - KEYS_MALFORMED:   response body unparseable
 *   - PLATFORM_RESPONSE: non-2xx HTTP
 */
export async function loadKeyDirectory(
  options: KeyDirectoryOptions,
): Promise<KeyDirectory> {
  if (options.source === "local") {
    if (!options.localKeys) {
      throw new AuditorError({
        code: "INVALID_INPUT",
        message: "source=local requires localKeys to be provided",
      });
    }
    const validated = options.localKeys.map(assertValidKey);
    return new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: validated,
    });
  }
  // Platform source — fetch over HTTP.
  const url = options.platformKeysUrl ?? DEFAULT_PLATFORM_KEYS_URL;
  const fetchFn = options.httpFetch ?? defaultFetch();
  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await fetchFn(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch (e) {
    throw asAuditorError(
      e,
      "KEYS_UNAVAILABLE",
      `failed to fetch verification keys from ${url}`,
    );
  }
  if (!response.ok) {
    let body = "";
    try {
      body = await response.text();
    } catch {
      // ignore
    }
    throw new AuditorError({
      code: "PLATFORM_RESPONSE" as AuditorErrorCode,
      message: `key directory returned HTTP ${response.status}`,
      detail: { status: response.status, body: body.slice(0, 256) },
    });
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch (e) {
    throw asAuditorError(
      e,
      "KEYS_MALFORMED",
      "key directory response was not valid JSON",
    );
  }
  if (!isRuntimeKeysResponse(parsed)) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message:
        "key directory response did not match the runtime_keys.v1 envelope",
    });
  }
  const validated = parsed.data.keys.map(assertValidKey);
  return new KeyDirectory({
    source: "platform",
    snapshotId: parsed.data.snapshotId ?? null,
    issuedAt: parsed.data.issuedAt,
    keys: validated,
  });
}

// ─────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────

function assertValidKey(k: VerificationKey, index?: number): VerificationKey {
  const label = index === undefined ? "key" : `keys[${index}]`;
  if (typeof k !== "object" || k === null) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `${label} is not an object`,
    });
  }
  for (const f of ["keyId", "algorithm", "publicKey", "notBefore"] as const) {
    if (typeof k[f] !== "string") {
      throw new AuditorError({
        code: "KEYS_MALFORMED",
        message: `${label}.${f} must be a string`,
      });
    }
  }
  if (k.notAfter !== null && typeof k.notAfter !== "string") {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `${label}.notAfter must be a string or null`,
    });
  }
  if (k.revokedAt !== null && typeof k.revokedAt !== "string") {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `${label}.revokedAt must be a string or null`,
    });
  }
  const algo: SignatureAlgorithm = k.algorithm;
  if (algo !== "ed25519") {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `${label}.algorithm '${k.algorithm}' is not supported (only 'ed25519')`,
    });
  }
  return k;
}

function isRuntimeKeysResponse(v: unknown): v is RuntimeKeysResponse {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (o["ok"] !== true) return false;
  if (typeof o["contractVersion"] !== "string") return false;
  const data = o["data"] as Record<string, unknown> | undefined;
  if (!data || typeof data !== "object") return false;
  if (!Array.isArray(data["keys"])) return false;
  if (typeof data["issuedAt"] !== "string") return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────
// Default fetch — kept behind a thunk so tests can inject without
// touching the global.
// ─────────────────────────────────────────────────────────────────────

function defaultFetch(): FetchLike {
  // The cast assumes Node 18+ (or a polyfilled global fetch). If the
  // host lacks fetch, the caller must supply `httpFetch`.
  const g = globalThis as { fetch?: FetchLike };
  if (typeof g.fetch !== "function") {
    return () =>
      Promise.reject(
        new AuditorError({
          code: "KEYS_UNAVAILABLE",
          message:
            "no global fetch available; supply httpFetch or use source=local",
        }),
      );
  }
  return g.fetch.bind(globalThis);
}
