// @enfinitos/sdk-auditor — hash helpers.
//
// Web-compatible by default. The SDK ships SHA-256 via @noble/hashes
// — pure TypeScript, no native bindings, audited, runs in Node /
// browsers / Cloudflare Workers / Deno / Bun. The previous version
// of this file required `node:crypto`, which made the auditor
// unusable in a browser tab; that was the wrong default for a
// library whose job is to verify proof packs *anywhere*.
//
// The auditor SDK uses sha256 in four slightly different shapes, and
// keeping them distinct matters because the platform does too:
//
//   1. **Plain hex.**   ProofRecord.afterHash is `sha256(payloadCanonical)`
//                       emitted as **bare hex** (no `sha256:` prefix).
//                       Matches the proof receipt's `payloadHash` static
//                       on apps/api/src/services/spatialChain/proofService.ts.
//
//   2. **Prefixed hex.** Rights / basis / offer / challenge hashes are
//                       `"sha256:<hex>"`. Matches the platform's
//                       hashRight / hashBasis / hashOffer.
//
//   3. **Meter idemKey.** sha256(`<proofReceiptId>|<unitType>`) emitted
//                       as bare hex. Matches meterService.ts.
//
//   4. **Settlement idemKey.** sha256(`<meterIdemKey>|<partyRole>`),
//                       bare hex. Matches settlementService.ts.
//
// Keeping these as separate named functions is verbose but cheap, and
// it removes a class of bugs where the wrong prefix flavour gets used
// for the wrong artefact.

import { sha256 as nobleSha256 } from "@noble/hashes/sha256";

// Single TextEncoder instance — UTF-8 is the only encoding the SDK
// uses and pinning it here makes the byte-input policy unambiguous.
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

/**
 * sha256 hex of a string — the raw form. Matches Node's
 * `createHash("sha256").update(s).digest("hex")` exactly, and
 * @noble/hashes is byte-equivalent across runtimes.
 *
 * Used directly for ProofRecord.afterHash verification.
 */
export function sha256Hex(input: string): string {
  return bytesToHex(nobleSha256(TEXT_ENCODER.encode(input)));
}

/**
 * sha256 hex with the `"sha256:"` prefix the rights/basis/offer
 * chains use.
 */
export function sha256HexPrefixed(input: string): string {
  return `sha256:${sha256Hex(input)}`;
}

/**
 * MeterRecord idemKey reconstruction — `sha256(proofReceiptId|unitType)`.
 *
 * The auditor uses this to rebuild every meter record's expected
 * idemKey and confirms it matches the one the platform shipped.
 */
export function meterIdemKey(proofReceiptId: string, unitType: string): string {
  return sha256Hex(`${proofReceiptId}|${unitType}`);
}

/**
 * SettlementLine idemKey reconstruction —
 * `sha256(meterRecordIdemKey|partyRole)`.
 */
export function settlementIdemKey(
  meterRecordIdemKey: string,
  partyRole: string,
): string {
  return sha256Hex(`${meterRecordIdemKey}|${partyRole}`);
}

/**
 * Constant-time byte comparison. Used wherever the SDK compares
 * cryptographic material (signatures, hashes) — avoids leaking
 * partial-match timing to a hostile auditor.
 *
 * Note: the SDK is single-threaded and the audit context is offline
 * (no adversarial timing channel in practice) — but constant-time
 * compare costs nothing and is the right default.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Constant-time hex-string comparison — wraps constantTimeEqual after
 * encoding the strings to UTF-8 bytes. Length-prefixed early-out is
 * already constant-time (length is non-secret).
 */
export function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return constantTimeEqual(TEXT_ENCODER.encode(a), TEXT_ENCODER.encode(b));
}
