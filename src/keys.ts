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
} from "./errors";
import type {
  RuntimeKeysResponse,
  SignatureAlgorithm,
  VerificationKey,
} from "./types";

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
  /**
   * Pinned root public key, base64url-encoded (unpadded), per ADR-0011.
   * When supplied, the auditor SDK verifies the `directorySignature` on
   * the platform response before trusting any of the contained keys.
   * Closes MC-1 (key-directory MITM substitution).
   *
   * Strict-mode: if `rootPublicKey` is supplied but the platform
   * response carries no `directorySignature`, the load fails with
   * `KEYS_MALFORMED`. This is the right posture once the platform
   * defaults to v2 emission — set the root key on the auditor and the
   * SDK refuses to trust unsigned directories.
   *
   * Permissive mode: if `rootPublicKey` is NOT supplied, the SDK falls
   * back to TLS-only trust on the directory (the v1 posture). Used
   * during the v1→v2 migration and for sandbox / local-test usage.
   */
  rootPublicKey?: string;
  /**
   * Identifier of the root key (matched against the
   * `directorySignature.rootKeyId` field). Required when
   * `rootPublicKey` is supplied so a future key rotation can be
   * detected unambiguously.
   */
  rootKeyId?: string;
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

  // ADR-0011 (MC-1): if the caller supplied a pinned root public key, the
  // platform response MUST carry a directorySignature, and it MUST verify
  // against that root key. This closes the MITM-substitution attack on the
  // key directory.
  //
  // Strict-mode semantics: a configured rootPublicKey with no signature in
  // the response is treated as a tampered response — we fail closed with
  // KEYS_MALFORMED rather than silently fall back to TLS-only trust.
  if (options.rootPublicKey) {
    await verifyDirectorySignature(parsed, {
      rootPublicKey: options.rootPublicKey,
      ...(options.rootKeyId !== undefined ? { rootKeyId: options.rootKeyId } : {}),
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
// ADR-0011 (MC-1): root-signed directory verification
//
// Lazy-imported to keep the Ed25519 + canonical-JSON paths out of the
// import graph when the caller doesn't pin a root key. Once root-key
// pinning becomes the default (Phase 2 in ADR-0011), this can move to
// the top-level imports.
// ─────────────────────────────────────────────────────────────────────

async function verifyDirectorySignature(
  parsed: RuntimeKeysResponse,
  opts: { rootPublicKey: string; rootKeyId?: string },
): Promise<void> {
  // Lazy-load to avoid pulling Ed25519 + canonicaliser into bundles that
  // don't use root-key pinning.
  const [{ canonicalSortKeys, base64UrlDecode }, ed] = await Promise.all([
    import("./canonicalJson"),
    import("@noble/ed25519"),
  ]);

  const sig = parsed.directorySignature;
  if (!sig) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message:
        "rootPublicKey is configured but the platform response carried no directorySignature. Refusing to trust unsigned key directory.",
    });
  }
  if (typeof sig.signature !== "string" || typeof sig.rootKeyId !== "string") {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: "directorySignature shape is invalid",
    });
  }
  if (opts.rootKeyId && sig.rootKeyId !== opts.rootKeyId) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `directorySignature.rootKeyId (${JSON.stringify(
        sig.rootKeyId,
      )}) did not match the configured rootKeyId (${JSON.stringify(
        opts.rootKeyId,
      )}). Root key may have rotated.`,
    });
  }
  if (sig.algorithm !== "ed25519") {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `directorySignature.algorithm '${sig.algorithm}' not supported (only ed25519)`,
    });
  }

  // Reproduce the signing input deterministically. Per ADR-0011 the
  // platform signs `canonical(data) + "|" + rootKeyId` where canonical()
  // uses the same sort-keys serialisation as proof packs.
  // `canonicalSortKeys` already returns the canonical JSON string, so we
  // concatenate directly without an extra JSON.stringify wrap.
  const canonicalBody = canonicalSortKeys(parsed.data);
  const signingInput = `${canonicalBody}|${sig.rootKeyId}`;
  const messageBytes = new TextEncoder().encode(signingInput);

  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = base64UrlDecode(opts.rootPublicKey);
    signature = base64UrlDecode(sig.signature);
  } catch (decodeErr) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `directorySignature decode failed: ${String(
        (decodeErr as Error).message,
      )}`,
    });
  }

  if (publicKey.length !== 32) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `rootPublicKey must decode to 32 bytes (got ${publicKey.length})`,
    });
  }
  if (signature.length !== 64) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `directorySignature must decode to 64 bytes (got ${signature.length})`,
    });
  }

  let ok = false;
  try {
    ok = await ed.verify(signature, messageBytes, publicKey);
  } catch (verifyErr) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message: `directorySignature verification threw: ${String(
        (verifyErr as Error).message,
      )}`,
    });
  }
  if (!ok) {
    throw new AuditorError({
      code: "KEYS_MALFORMED",
      message:
        "directorySignature did not verify against the configured rootPublicKey. Reject the directory.",
    });
  }
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
