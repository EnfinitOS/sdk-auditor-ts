// @enfinitos/sdk-auditor — hash helpers.
//
// The auditor SDK uses sha256 in three slightly different shapes, and
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

import { createHash } from "node:crypto";

/**
 * sha256 hex of a string — the raw form. Matches Node's
 * `createHash("sha256").update(s).digest("hex")` exactly.
 *
 * Used directly for ProofRecord.afterHash verification.
 */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
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
 * decoding from hex. Throws if either side is not valid hex.
 */
export function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  // Hex is single-byte-per-2-chars; safe to encode as ASCII
  return constantTimeEqual(
    new Uint8Array(Buffer.from(a, "utf8")),
    new Uint8Array(Buffer.from(b, "utf8")),
  );
}
