// @enfinitos/sdk-auditor — canonical JSON encoder.
//
// Why this file exists
// ────────────────────
// The auditor SDK must produce byte-exact equality with the
// platform's canonical encoder, because the Ed25519 signature is
// computed over the canonical bytes — a single whitespace or
// key-order difference would make every verification fail.
//
// The platform has TWO canonical encoders, and we have to match BOTH:
//
//   1. **Field-ordered (proof receipts).**
//      apps/api/src/services/spatialChain/canonicalise.ts emits the
//      ProofReceiptPayload fields in a hand-coded declared order
//      (version, receiptId, correlationId, …). The auditor's
//      `canonicaliseProofPayload` here replicates that order
//      verbatim. This is the encoding the proof receipts'
//      Ed25519 signatures are over.
//
//   2. **Sort-key recursive (rights/basis/offer/meter/settlement).**
//      apps/api/src/modules/rights/service.ts uses
//      `canonicalJson(value)` — a recursive sort-key encoder. The
//      auditor's `canonicalSortKeys` here is the same algorithm.
//      Used wherever the platform emits content-addressable hashes
//      over composite objects (right/basis/offer hashes, meter
//      idem keys are stringly so don't need it).
//
// We DELIBERATELY do not implement a single "smart" encoder that
// detects which mode to use — that would be one source of bugs
// pretending to be two solutions. Callers pick the encoder
// matching the shape they are hashing.
//
// Number policy
// ─────────────
// JSON.stringify on numbers:
//   - integers: no trailing zeros, no exponent until ~21 digits
//   - floats: minimal round-trip representation (ECMA 262 "ToString
//     Applied to Number Type")
// The platform relies on this, so we relay through JSON.stringify
// rather than reformatting numbers. The risk surface here is `NaN`,
// `Infinity`, and `-0` — none of which should ever appear in a proof
// receipt, but if they do we throw rather than silently emit JSON
// nulls (which is what JSON.stringify defaults to for NaN/Infinity).

import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import type { ProofReceiptPayload } from "./types.js";

// Single TextEncoder instance — UTF-8 is the only encoding the SDK
// uses for canonical bytes. Pinning it here makes the conversion
// policy explicit and unambiguous.
const TEXT_ENCODER = new TextEncoder();

const HEX_ALPHABET = "0123456789abcdef";
function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    out += HEX_ALPHABET[(b >> 4) & 0xf];
    out += HEX_ALPHABET[b & 0xf];
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────
// Field-ordered encoder — exact platform parity for ProofReceiptPayload
// ─────────────────────────────────────────────────────────────────────

/**
 * The canonical field order for a v1 ProofReceiptPayload. Lifted
 * verbatim from the platform's
 * apps/api/src/services/spatialChain/canonicalise.ts.
 *
 * The auditor SDK refuses to re-canonicalise if a record's payload
 * carries unknown keys — the platform never emits unknown keys, so
 * the presence of one means either tampering or a version skew the
 * SDK should not silently accept.
 */
const PROOF_PAYLOAD_FIELDS = [
  "version",
  "receiptId",
  "correlationId",
  "spatialAnchorId",
  "spatialPlacementId",
  "issuedAt",
  "renderedAt",
  "dwellMs",
  "nonce",
  "witness",
] as const;

/**
 * canonicaliseProofPayload — produces the exact bytes the platform
 * signed.
 *
 * Format (must match apps/api/src/services/spatialChain/canonicalise.ts
 * byte-for-byte):
 *
 *   {"version":"1","receiptId":"…","correlationId":null,…}
 *
 * - Keys in PROOF_PAYLOAD_FIELDS order
 * - No whitespace between key/value/comma
 * - Each value JSON.stringified individually (strings → "..", null
 *   stays as null, numbers as minimal representation)
 *
 * Throws if a non-finite number is encountered. Returns the raw
 * canonical string; the caller hashes / signs / verifies it.
 */
export function canonicaliseProofPayload(p: ProofReceiptPayload): string {
  assertFiniteOrThrow(p.dwellMs, "dwellMs");

  // We project explicitly (not Object.entries) so unknown keys can't
  // sneak in. This also guarantees a deterministic order even if a
  // future TypeScript engine changes object iteration semantics.
  const body = PROOF_PAYLOAD_FIELDS.map((field) => {
    const value = p[field];
    return `${JSON.stringify(field)}:${JSON.stringify(value)}`;
  }).join(",");
  return `{${body}}`;
}

/**
 * The full signing input — `<canonical-payload>|<keyId>`, matching
 * `canonicaliseProofSigningInput` in the platform. The Ed25519
 * signature is over the UTF-8 bytes of this string.
 */
export function canonicaliseProofSigningInput(
  payload: ProofReceiptPayload,
  keyId: string,
): string {
  return `${canonicaliseProofPayload(payload)}|${keyId}`;
}

// ─────────────────────────────────────────────────────────────────────
// Sort-key recursive encoder — exact platform parity for rights/meter
// ─────────────────────────────────────────────────────────────────────

/**
 * canonicalSortKeys — the platform's generic canonical encoder used
 * for hashRight / hashBasis / hashOffer.
 *
 * Algorithm (replicated from rights/service.ts canonicalJson):
 *   - If value is null, an array, or a primitive: emit as-is via
 *     JSON.stringify.
 *   - If value is an object: emit with keys sorted lexicographically,
 *     recursing into each value.
 *
 * **Arrays are NOT sorted** — their order is significant and the
 * platform relies on that. Same goes for arrays of objects: each
 * inner object has its keys sorted but the outer array order is
 * preserved verbatim.
 *
 * **Stability across runtimes:** we use `Array.prototype.sort` with
 * a deterministic locale-independent comparator (codepoint-by-codepoint
 * via `String#localeCompare` would be locale-dependent and is
 * therefore wrong). We use `<` / `>` operators which compare by UTF-16
 * code unit and match Node / browser / Deno.
 */
export function canonicalSortKeys(value: unknown): string {
  return JSON.stringify(value, (_key, input) => {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      return input;
    }
    const obj = input as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });
    const out: Record<string, unknown> = {};
    for (const k of sortedKeys) {
      out[k] = obj[k];
    }
    return out;
  });
}

// ─────────────────────────────────────────────────────────────────────
// Base64url
// ─────────────────────────────────────────────────────────────────────

/**
 * Base64url-encode a byte slice. Matches the platform's
 * `base64UrlEncode` byte-for-byte:
 *   - "+" → "-"
 *   - "/" → "_"
 *   - trailing "=" stripped
 *
 * Uses `btoa` rather than Node's `Buffer` so the SDK runs in
 * browsers and Cloudflare Workers without a polyfill. Building the
 * binary string in 32K chunks avoids the call-stack blow-up
 * `String.fromCharCode(...verylarge)` is famous for.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Base64url-decode. Accepts both padded and unpadded input. Returns
 * a Uint8Array so the public API stays runtime-neutral.
 */
export function base64UrlDecode(s: string): Uint8Array {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const normal = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normal);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────
// Number policy helper
// ─────────────────────────────────────────────────────────────────────

function assertFiniteOrThrow(n: number, label: string): void {
  if (!Number.isFinite(n)) {
    throw new Error(
      `canonicalJson: non-finite number for ${label} (${String(n)}). Proof receipts must not contain NaN / Infinity.`,
    );
  }
}

// ─────────────────────────────────────────────────────────────────────
// Hashing helpers re-exported for callers that want a one-liner
// ─────────────────────────────────────────────────────────────────────

/**
 * sha256 of a canonical string, returned as `sha256:<hex>` — the
 * shape the rights / basis / offer chain uses. The proof chain uses
 * raw hex (no `sha256:` prefix) — see hashing.ts for that path.
 *
 * This helper lives here rather than in hashing.ts because it is
 * shaped against `canonicalSortKeys` callers (rights/basis/offer)
 * and pairs naturally with the encoder.
 */
export function sha256Prefixed(canonical: string): string {
  return `sha256:${bytesToHex(nobleSha256(TEXT_ENCODER.encode(canonical)))}`;
}
