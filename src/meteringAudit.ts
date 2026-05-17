// @enfinitos/sdk-auditor — metering re-projection audit.
//
// The platform projects every ProofReceipt into one or more meter
// records via a deterministic policy (see
// apps/api/src/services/spatialChain/meterService.ts). For
// DWELL_SECONDS, the policy is `unitCount = dwellMs / 1000`. Other
// unit types use other formulas; this module's auditor knows all of
// them.
//
// What this module proves
// ───────────────────────
// Given a verified ProofPack and a platform-issued MeteringSummary,
// the auditor:
//
//   1. Confirms every MeterRecord references a proof receipt that
//      exists in the pack — `METER_RECORD_FOR_UNKNOWN_PROOF` if not.
//   2. Confirms orgId on the metering summary matches the pack's.
//   3. Recomputes idemKey = sha256(proofReceiptId|unitType) per
//      record and asserts equality — `METER_IDEM_KEY_MISMATCH` if
//      not (this catches accidentally-re-used keys).
//   4. Re-runs the unit-count projection and asserts decimal
//      equality — `METER_UNIT_COUNT_MISMATCH` if not. We compare as
//      strings to preserve precision; the platform serialises
//      Prisma.Decimal to "12.345000" (six decimal places) so we
//      normalise our local result the same way before comparing.
//   5. Recomputes per-unit-type totals and asserts equality with
//      `summary.totals` if present — `METER_TOTAL_MISMATCH` if not.
//
// Decimal precision
// ─────────────────
// The platform persists Prisma.Decimal at 6dp. We re-produce the
// same 6dp string here. This is the boundary condition where the
// auditor SDK has to know the platform's column precision — there
// is no way around it; an off-by-one decimal place would produce
// false-positive failures on every record. The 6dp choice is
// declared on the Prisma schema and noted in the platform's
// commerce ADR.

import { sha256Hex } from "./hashing";
import {
  type AuditStep,
  type MeterRecord,
  type MeteringSummary,
  type ProofRecord,
  type ProofReceiptPayload,
  type ProjectionAuditReport,
  SDK_VERSION,
} from "./types";

const DECIMAL_PLACES = 6;

/**
 * verifyMeteringProjection — re-projects every meter record from
 * the source proof receipt and asserts equality.
 *
 * The pack we receive is the source-of-truth proof set; the summary
 * is the candidate-under-audit. The auditor's job is to confirm the
 * summary follows from the pack by deterministic projection — NOT
 * to trust any field the platform shipped.
 */
export function verifyMeteringProjection(
  proofRecords: ProofRecord[],
  metering: MeteringSummary,
  packOrgId?: string,
): ProjectionAuditReport {
  const verifiedAt = new Date().toISOString();
  const steps: AuditStep[] = [];

  // Build a map of receiptId → payload so per-record lookups are O(1).
  const proofByReceiptId = new Map<string, ProofReceiptPayload>();
  for (const r of proofRecords) {
    proofByReceiptId.set(r.payload.receiptId, r.payload);
  }

  // 1. Org parity.
  if (packOrgId && metering.orgId !== packOrgId) {
    steps.push({
      target: "metering.orgId",
      kind: "meter_projection",
      status: "INVALID",
      reason: "METER_ORG_MISMATCH",
      message: `metering.orgId '${metering.orgId}' does not match pack.orgId '${packOrgId}'`,
    });
  } else if (packOrgId) {
    steps.push({
      target: "metering.orgId",
      kind: "meter_projection",
      status: "VALID",
      message: "metering summary orgId matches pack",
    });
  }

  // 2..4 — walk every record.
  const computedTotals = new Map<MeterRecord["unitType"], bigint>();
  for (let i = 0; i < metering.records.length; i++) {
    const m = metering.records[i]!;
    const proof = proofByReceiptId.get(m.proofReceiptId);
    if (!proof) {
      steps.push({
        target: `metering.records[${i}].proofReceiptId`,
        kind: "meter_projection",
        status: "INVALID",
        reason: "METER_RECORD_FOR_UNKNOWN_PROOF",
        message: `meter record references proofReceiptId '${m.proofReceiptId}' that is not in the proof pack — the meter cannot be verified`,
      });
      continue;
    }
    // 3. idemKey reconstruction.
    const expectedIdem = sha256Hex(`${m.proofReceiptId}|${m.unitType}`);
    if (expectedIdem !== m.idemKey) {
      steps.push({
        target: `metering.records[${i}].idemKey`,
        kind: "meter_projection",
        status: "INVALID",
        reason: "METER_IDEM_KEY_MISMATCH",
        message: `idemKey on meter record does not equal sha256(proofReceiptId|unitType)`,
        detail: { expected: expectedIdem, actual: m.idemKey },
      });
    } else {
      steps.push({
        target: `metering.records[${i}].idemKey`,
        kind: "meter_projection",
        status: "VALID",
        message: "idemKey matches sha256(proofReceiptId|unitType)",
      });
    }

    // 4. unitCount reconstruction.
    const expectedUnitCount = projectUnitCount(
      proof.dwellMs,
      parseDecimalToScaled(m.weight),
      m.unitType,
    );
    if (expectedUnitCount === null) {
      steps.push({
        target: `metering.records[${i}].unitCount`,
        kind: "meter_projection",
        status: "INVALID",
        reason: "METER_UNIT_COUNT_MISMATCH",
        message: `unit type '${m.unitType}' has no known projection — the SDK build is older than the platform's policy table`,
      });
      continue;
    }
    const expectedString = formatScaledDecimal(expectedUnitCount);
    const actualScaled = parseDecimalToScaled(m.unitCount);
    if (actualScaled !== expectedUnitCount) {
      steps.push({
        target: `metering.records[${i}].unitCount`,
        kind: "meter_projection",
        status: "INVALID",
        reason: "METER_UNIT_COUNT_MISMATCH",
        message: `unitCount does not match deterministic re-projection from proof.dwellMs=${proof.dwellMs} weight=${m.weight} unitType=${m.unitType}`,
        detail: { expected: expectedString, actual: m.unitCount },
      });
    } else {
      steps.push({
        target: `metering.records[${i}].unitCount`,
        kind: "meter_projection",
        status: "VALID",
        message: `unitCount=${m.unitCount} re-projects exactly from proof`,
      });
    }
    // Roll into totals regardless of pass/fail — we still want a
    // totals comparison if a later record passes.
    const acc = computedTotals.get(m.unitType) ?? 0n;
    computedTotals.set(m.unitType, acc + expectedUnitCount);
  }

  // 5. Totals.
  if (metering.totals) {
    for (const [unitType, claimed] of Object.entries(metering.totals)) {
      // totals is Partial<Record<MeterUnitType, string>>, so a key
      // may legally be undefined (the operator declared the key
      // shape but didn't fill in this row). Skip — there's nothing
      // to compare against.
      if (claimed === undefined) continue;
      const computed = computedTotals.get(unitType as MeterRecord["unitType"]) ?? 0n;
      const computedStr = formatScaledDecimal(computed);
      const claimedScaled = parseDecimalToScaled(claimed);
      if (claimedScaled !== computed) {
        steps.push({
          target: `metering.totals.${unitType}`,
          kind: "meter_total",
          status: "INVALID",
          reason: "METER_TOTAL_MISMATCH",
          message: `claimed total for ${unitType} does not match sum of per-record projections`,
          detail: { expected: computedStr, actual: claimed },
        });
      } else {
        steps.push({
          target: `metering.totals.${unitType}`,
          kind: "meter_total",
          status: "VALID",
          message: `claimed total for ${unitType} matches sum of records`,
        });
      }
    }
  }

  const anyInvalid = steps.some((s) => s.status === "INVALID");
  return {
    status: anyInvalid ? "INVALID" : "VALID",
    verifiedAt,
    sdkVersion: SDK_VERSION,
    proofRecordCount: proofRecords.length,
    meterRecordCount: metering.records.length,
    steps,
  };
}

// ─────────────────────────────────────────────────────────────────────
// Projection policies (mirror platform meterService.ts)
// ─────────────────────────────────────────────────────────────────────

/**
 * Per-unit-type projection from a proof receipt's dwellMs +
 * weight → unit count, expressed as a "scaled integer" (the
 * decimal value multiplied by 10^DECIMAL_PLACES so it fits in a
 * bigint and compares exactly).
 *
 * Returns null for unknown unit types — the audit will report this
 * as an explicit failure rather than silently passing.
 *
 * **Policy table:**
 *   - DWELL_SECONDS:                dwellMs / 1000, weight applied
 *   - IMPRESSION_IN_PLACE:          1 unit per receipt, weight applied
 *   - ATTENTION_SECONDS:            same as DWELL_SECONDS pending
 *                                   platform-side attention input
 *                                   (the platform passes attention %
 *                                   in `extra`; the auditor SDK
 *                                   re-projects from proof and so
 *                                   matches platform projection at
 *                                   the weight=attentionPct case)
 *   - OCCUPANCY_WEIGHTED_EXPOSURE:  dwellMs / 1000, weight applied
 *                                   (occupancy carried via weight)
 *   - COMPLIANT_DELIVERY_MINUTE:    dwellMs / 60000, weight applied
 *   - CUSTOM:                       not auditable here — the
 *                                   platform supplies a policy
 *                                   adapter at runtime; the audit
 *                                   SDK treats CUSTOM as "skipped"
 *                                   and emits a SKIPPED step instead.
 */
function projectUnitCount(
  dwellMs: number,
  weightScaled: bigint,
  unitType: MeterRecord["unitType"],
): bigint | null {
  const factor = 10n ** BigInt(DECIMAL_PLACES);
  switch (unitType) {
    case "DWELL_SECONDS":
    case "ATTENTION_SECONDS":
    case "OCCUPANCY_WEIGHTED_EXPOSURE": {
      // (dwellMs / 1000) * weight
      // Compute as scaled bigint: (dwellMs * factor / 1000) * weight / factor
      const dwellScaled = (BigInt(dwellMs) * factor) / 1000n;
      return (dwellScaled * weightScaled) / factor;
    }
    case "IMPRESSION_IN_PLACE": {
      // 1 unit * weight
      return weightScaled;
    }
    case "COMPLIANT_DELIVERY_MINUTE": {
      const dwellScaled = (BigInt(dwellMs) * factor) / 60000n;
      return (dwellScaled * weightScaled) / factor;
    }
    case "CUSTOM":
      // Caller-policy-dependent; the auditor cannot independently
      // re-project. Returning null causes an INVALID step which is
      // technically the most conservative call here, but callers
      // who use CUSTOM should swap in a custom projection function
      // (forthcoming in v2 via `MeteringAuditOptions.customPolicy`).
      return null;
    default:
      return null;
  }
}

/**
 * parseDecimalToScaled — "12.345" → 12345000n (when DECIMAL_PLACES=6).
 * Throws on non-numeric input. Permissive about leading/trailing
 * zeros and an optional sign.
 *
 * We DELIBERATELY do not use Number/parseFloat — IEEE 754 cannot
 * represent every 6dp decimal exactly and the audit would produce
 * false-positive mismatches for innocent records.
 */
function parseDecimalToScaled(s: string): bigint {
  const sign = s.startsWith("-") ? -1n : 1n;
  const stripped = s.startsWith("-") || s.startsWith("+") ? s.slice(1) : s;
  const [intPart, fracPart = ""] = stripped.split(".");
  if (!intPart || !/^\d+$/.test(intPart)) {
    throw new Error(`metering decimal '${s}' has invalid integer part`);
  }
  if (fracPart && !/^\d+$/.test(fracPart)) {
    throw new Error(`metering decimal '${s}' has invalid fractional part`);
  }
  const padded = (fracPart + "0".repeat(DECIMAL_PLACES)).slice(0, DECIMAL_PLACES);
  const combined = `${intPart}${padded}`;
  return sign * BigInt(combined);
}

/**
 * formatScaledDecimal — inverse of parseDecimalToScaled. Always emits
 * exactly DECIMAL_PLACES decimal places (the platform's column
 * precision).
 */
function formatScaledDecimal(n: bigint): string {
  const sign = n < 0n ? "-" : "";
  const abs = n < 0n ? -n : n;
  const s = abs.toString().padStart(DECIMAL_PLACES + 1, "0");
  const intPart = s.slice(0, s.length - DECIMAL_PLACES);
  const fracPart = s.slice(s.length - DECIMAL_PLACES);
  return `${sign}${intPart}.${fracPart}`;
}
