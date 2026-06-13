// @enfinitos/sdk-auditor — settlement reconciliation audit.
//
// The platform projects an accepted MeterRecord into one or more
// SettlementLine rows via a share table (see
// apps/api/src/services/spatialChain/settlementService.ts). For
// every meter record there's a `grossAmountCents` (pricing input)
// and a set of party-role splits. The default split is "100% to
// TENANT"; multi-party splits add VENUE / CUSTOMER / PLATFORM rows.
//
// What this module proves
// ───────────────────────
// Given a MeteringSummary (already audited as projecting from
// proofs) and a SettlementSummary, the auditor:
//
//   1. Confirms orgId parity with metering.
//   2. For every settlement line, confirms it references a meter
//      record in the metering summary (METER_IDEM_KEY lookup).
//   3. Confirms the per-meter shares sum to 1 — partial coverage
//      means the platform is dropping money.
//   4. Recomputes `amountCents = round(grossAmountCents * share)`
//      and asserts equality — `SETTLEMENT_AMOUNT_MISMATCH` if not.
//   5. Confirms settlement-line idemKey reconstructs as
//      sha256(meterRecordIdemKey|partyRole|ledgerAccountCode) — content-hash
//      based, so production settlement lines are independently recomputable
//      (CRYPTO-01 / settlement.v2).
//   6. Recomputes per-summary totals (grossCents, netToTenantCents,
//      platformFeeCents) and asserts equality if `summary.totals`
//      is provided.
//
// Rounding policy
// ───────────────
// The platform rounds amounts to the nearest minor unit using
// banker's rounding (half-to-even) at the line level, with the
// remainder reabsorbed into the largest-share line — this prevents
// rounding gaps from corrupting downstream double-entry posting.
//
// The auditor implements the same rule. The risk of a stale auditor
// SDK is the rounding policy changes server-side; we declare our
// version in the schema so a platform-side bump triggers an explicit
// audit-SDK upgrade.

import { settlementIdemKey, settlementIdemKeyV1 } from "./hashing";
import {
  SDK_VERSION,
  type AuditStep,
  type MeteringSummary,
  type SettlementAuditReport,
  type SettlementLine,
  type SettlementSummary,
} from "./types";

/**
 * verifySettlementReconciliation — re-derive every settlement line
 * and assert equality with the candidate summary.
 */
export function verifySettlementReconciliation(
  metering: MeteringSummary,
  settlement: SettlementSummary,
): SettlementAuditReport {
  const verifiedAt = new Date().toISOString();
  const steps: AuditStep[] = [];

  // 1. Org parity.
  if (settlement.orgId !== metering.orgId) {
    steps.push({
      target: "settlement.orgId",
      kind: "settlement_line",
      status: "INVALID",
      reason: "SETTLEMENT_ORG_MISMATCH",
      message: `settlement.orgId '${settlement.orgId}' does not match metering.orgId '${metering.orgId}'`,
    });
  } else {
    steps.push({
      target: "settlement.orgId",
      kind: "settlement_line",
      status: "VALID",
      message: "settlement orgId matches metering",
    });
  }

  // Build lookup: meterIdemKey → MeterRecord
  const meterByIdem = new Map(metering.records.map((r) => [r.idemKey, r]));

  // Group settlement lines by meterRecordIdemKey for share-sum check.
  const linesByMeter = new Map<string, SettlementLine[]>();
  for (const line of settlement.lines) {
    const acc = linesByMeter.get(line.meterRecordIdemKey) ?? [];
    acc.push(line);
    linesByMeter.set(line.meterRecordIdemKey, acc);
  }

  // CRYPTO-04: recompute each meter's deterministic integer split exactly
  // (floor per share + residual reabsorbed into the largest-share line, ties
  // broken by the smaller partyRole) — the byte-for-byte mirror of the
  // platform's `splitGrossDeterministically` — and require exact-cent
  // equality per line. No tolerance band: production amounts sum to gross by
  // construction, so any deviation is a real discrepancy.
  const expectedAmountByLine = new Map<SettlementLine, number>();
  for (const [meterIdem, group] of linesByMeter) {
    const gross = settlement.meterGross[meterIdem];
    if (gross === undefined) continue; // flagged per-line below
    const sharesScaled = group.map((l) => parseDecimalToScaled(l.share, 6));
    const partyRoles = group.map((l) => l.partyRole);
    const split = deterministicSplitCents(gross, sharesScaled, partyRoles);
    group.forEach((l, idx) => expectedAmountByLine.set(l, split[idx]!));
  }

  // 2..5: walk every line.
  let computedGrossCents = 0;
  let computedNetToTenantCents = 0;
  let computedPlatformFeeCents = 0;

  for (let i = 0; i < settlement.lines.length; i++) {
    const line = settlement.lines[i]!;
    const meter = meterByIdem.get(line.meterRecordIdemKey);
    if (!meter) {
      steps.push({
        target: `settlement.lines[${i}].meterRecordIdemKey`,
        kind: "settlement_line",
        status: "INVALID",
        reason: "SETTLEMENT_LINE_FOR_UNKNOWN_METER",
        message: `settlement line references meterRecordIdemKey '${line.meterRecordIdemKey}' not in metering summary`,
      });
      continue;
    }
    // 5. idemKey reconstruction — VERSION-AWARE (VER-02). settlement.v2 uses
    // the 3-field content-hash key (CRYPTO-01); legacy settlement.v1 packs
    // used the 2-field `sha256(meterIdemKey|partyRole)`. Selecting by the
    // summary's schemaVersion keeps old proof packs verifiable instead of
    // flagging every v1 line as a mismatch.
    const isV2 = settlement.schemaVersion === "settlement.v2";
    const expectedIdem = isV2
      ? settlementIdemKey(line.meterRecordIdemKey, line.partyRole, line.ledgerAccountCode)
      : settlementIdemKeyV1(line.meterRecordIdemKey, line.partyRole);
    if (line.idemKey !== expectedIdem) {
      steps.push({
        target: `settlement.lines[${i}].idemKey`,
        kind: "settlement_line",
        status: "INVALID",
        reason: "SETTLEMENT_IDEM_KEY_MISMATCH",
        message: isV2
          ? `settlement-line idemKey does not equal sha256(meterIdemKey|partyRole|ledgerAccountCode)`
          : `settlement-line idemKey does not equal sha256(meterIdemKey|partyRole)`,
        detail: { expected: expectedIdem, actual: line.idemKey, schemaVersion: settlement.schemaVersion },
      });
    } else {
      steps.push({
        target: `settlement.lines[${i}].idemKey`,
        kind: "settlement_line",
        status: "VALID",
        message: "settlement idemKey matches reconstruction",
      });
    }

    // 4. amountCents reconstruction — exact-cent (CRYPTO-04).
    const gross = settlement.meterGross[line.meterRecordIdemKey];
    if (gross === undefined) {
      steps.push({
        target: `settlement.meterGross.${line.meterRecordIdemKey}`,
        kind: "settlement_line",
        status: "INVALID",
        reason: "SETTLEMENT_LINE_FOR_UNKNOWN_METER",
        message: `no gross amount for meterIdemKey '${line.meterRecordIdemKey}'`,
      });
      continue;
    }
    // Compare against the deterministic integer split recomputed above —
    // the largest-share line carries the rounding residual exactly, every
    // other line is `floor(gross * share)`. No tolerance band.
    const expected = expectedAmountByLine.get(line);
    if (expected === undefined || expected !== line.amountCents) {
      steps.push({
        target: `settlement.lines[${i}].amountCents`,
        kind: "settlement_line",
        status: "INVALID",
        reason: "SETTLEMENT_AMOUNT_MISMATCH",
        message: `amountCents does not equal the deterministic integer split of grossCents by share`,
        detail: {
          expected: expected ?? null,
          actual: line.amountCents,
          gross,
          share: line.share,
        },
      });
      continue;
    }
    steps.push({
      target: `settlement.lines[${i}].amountCents`,
      kind: "settlement_line",
      status: "VALID",
      message: `amountCents=${line.amountCents} matches deterministic split of gross=${gross} by share=${line.share}`,
    });
    computedGrossCents += line.amountCents; // sum across lines
    if (line.partyRole === "TENANT") computedNetToTenantCents += line.amountCents;
    if (line.partyRole === "PLATFORM") computedPlatformFeeCents += line.amountCents;
  }

  // 3. Per-meter share-sum check.
  for (const [meterIdem, group] of linesByMeter) {
    const sumScaled = group.reduce(
      (acc, l) => acc + parseDecimalToScaled(l.share, 6),
      0n,
    );
    if (sumScaled !== 1_000_000n) {
      steps.push({
        target: `settlement.lines[meter=${meterIdem}].share`,
        kind: "settlement_line",
        status: "INVALID",
        reason: "SETTLEMENT_SHARE_SUM_NOT_ONE",
        message: `shares for meter '${meterIdem}' sum to ${formatScaledDecimal(sumScaled, 6)}, not 1.000000`,
      });
    } else {
      steps.push({
        target: `settlement.lines[meter=${meterIdem}].share`,
        kind: "settlement_line",
        status: "VALID",
        message: `shares for meter '${meterIdem}' sum to 1.000000`,
      });
    }
  }

  // 6. Totals.
  if (settlement.totals) {
    const claimedGross = settlement.totals.grossCents;
    const claimedNet = settlement.totals.netToTenantCents;
    const claimedFee = settlement.totals.platformFeeCents;
    pushTotalCheck(steps, "grossCents", claimedGross, computedGrossCents);
    pushTotalCheck(steps, "netToTenantCents", claimedNet, computedNetToTenantCents);
    pushTotalCheck(steps, "platformFeeCents", claimedFee, computedPlatformFeeCents);
  }

  const anyInvalid = steps.some((s) => s.status === "INVALID");
  return {
    status: anyInvalid ? "INVALID" : "VALID",
    verifiedAt,
    sdkVersion: SDK_VERSION,
    meterRecordCount: metering.records.length,
    settlementLineCount: settlement.lines.length,
    steps,
  };
}

function pushTotalCheck(
  steps: AuditStep[],
  label: string,
  claimed: number,
  computed: number,
) {
  if (claimed !== computed) {
    steps.push({
      target: `settlement.totals.${label}`,
      kind: "settlement_total",
      status: "INVALID",
      reason: "SETTLEMENT_TOTAL_MISMATCH",
      message: `claimed ${label}=${claimed} does not match recomputed ${computed}`,
    });
  } else {
    steps.push({
      target: `settlement.totals.${label}`,
      kind: "settlement_total",
      status: "VALID",
      message: `${label}=${claimed} reconciles`,
    });
  }
}

/**
 * deterministicSplitCents — the auditor's mirror of the platform's
 * `splitGrossDeterministically` (apps/api settlementService.ts). Floors each
 * share's slice as `floor(gross * shareScaled / 1_000_000)` and reabsorbs the
 * residual (`gross − Σ floors`) into the largest-share line, ties broken by
 * the smaller partyRole (lexical). Deterministic and sums to exactly `gross`,
 * so settlement amounts are recomputable to the exact cent.
 */
function deterministicSplitCents(
  gross: number,
  sharesScaled: bigint[],
  partyRoles: string[],
): number[] {
  const floors = sharesScaled.map((s) =>
    Number((BigInt(gross) * s) / 1_000_000n),
  );
  const remainder = gross - floors.reduce((a, b) => a + b, 0);
  if (remainder !== 0 && floors.length > 0) {
    let target = 0;
    for (let i = 1; i < sharesScaled.length; i++) {
      if (
        sharesScaled[i]! > sharesScaled[target]! ||
        (sharesScaled[i]! === sharesScaled[target]! &&
          partyRoles[i]! < partyRoles[target]!)
      ) {
        target = i;
      }
    }
    floors[target]! += remainder;
  }
  return floors;
}

// ─────────────────────────────────────────────────────────────────────
// Decimal helpers (local copy — kept in this file because settlement
// uses a different DP than metering may, and we don't want a shared
// mutable global)
// ─────────────────────────────────────────────────────────────────────

function parseDecimalToScaled(s: string, places: number): bigint {
  const sign = s.startsWith("-") ? -1n : 1n;
  const stripped = s.startsWith("-") || s.startsWith("+") ? s.slice(1) : s;
  const [intPart, fracPart = ""] = stripped.split(".");
  if (!intPart || !/^\d+$/.test(intPart)) {
    throw new Error(`settlement decimal '${s}' has invalid integer part`);
  }
  if (fracPart && !/^\d+$/.test(fracPart)) {
    throw new Error(`settlement decimal '${s}' has invalid fractional part`);
  }
  const padded = (fracPart + "0".repeat(places)).slice(0, places);
  return sign * BigInt(`${intPart}${padded}`);
}

function formatScaledDecimal(n: bigint, places: number): string {
  const sign = n < 0n ? "-" : "";
  const abs = n < 0n ? -n : n;
  const s = abs.toString().padStart(places + 1, "0");
  const intPart = s.slice(0, s.length - places);
  const fracPart = s.slice(s.length - places);
  return `${sign}${intPart}.${fracPart}`;
}
