import { describe, expect, it } from "vitest";

import { settlementIdemKey, settlementIdemKeyV1 } from "../src/hashing.js";
import { verifySettlementReconciliation } from "../src/settlementAudit.js";
import type { MeteringSummary, SettlementSummary } from "../src/types.js";

import {
  buildMeteringSummary,
  buildMultiRecordChain,
  buildSettlementSummary,
  generateKey,
} from "./fixtures/builder.js";

describe("verifySettlementReconciliation", () => {
  it("passes for a 100%-tenant single-line projection", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(3, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    const report = verifySettlementReconciliation(metering, settlement);
    expect(report.status).toBe("VALID");
  });

  it("flags SETTLEMENT_LINE_FOR_UNKNOWN_METER for unknown idemKey", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.lines[0]!.meterRecordIdemKey = "ghost_meter_idem";
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_LINE_FOR_UNKNOWN_METER"),
    ).toBe(true);
  });

  it("flags SETTLEMENT_AMOUNT_MISMATCH when amountCents is wrong", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.lines[0]!.amountCents = settlement.lines[0]!.amountCents + 1000;
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_AMOUNT_MISMATCH"),
    ).toBe(true);
  });

  it("flags SETTLEMENT_IDEM_KEY_MISMATCH when idemKey is wrong", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.lines[0]!.idemKey = "0".repeat(64);
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_IDEM_KEY_MISMATCH"),
    ).toBe(true);
  });

  it("flags SETTLEMENT_SHARE_SUM_NOT_ONE when shares don't sum to 1", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(1, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.lines[0]!.share = "0.500000";
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_SHARE_SUM_NOT_ONE"),
    ).toBe(true);
  });

  it("flags SETTLEMENT_ORG_MISMATCH for mismatched orgId", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(1, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.orgId = "org_other";
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_ORG_MISMATCH"),
    ).toBe(true);
  });

  it("flags SETTLEMENT_TOTAL_MISMATCH for wrong totals", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.totals!.grossCents = 0;
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_TOTAL_MISMATCH"),
    ).toBe(true);
  });
});

// ── CRYPTO-04: exact-cent multi-party split ──────────────────────────────
//
// Production splits a meter's gross across party shares as a deterministic
// integer split (floor per share + residual reabsorbed into the largest-share
// line). The auditor mirrors that split and requires EXACT-cent equality —
// no ±band — so a single-cent discrepancy on any line, including the
// residual-bearing largest line, is caught.

function buildMultiPartySplit(): {
  metering: MeteringSummary;
  settlement: SettlementSummary;
} {
  const meterIdem = "meter_multiparty_x";
  const gross = 10001; // 0.7/0.25/0.05 → 7000.7 / 2500.25 / 500.05
  const metering: MeteringSummary = {
    schemaVersion: "metering.v1",
    orgId: "org_test",
    periodStart: "2027-01-01T00:00:00.000Z",
    periodEnd: "2027-02-01T00:00:00.000Z",
    records: [
      {
        idemKey: meterIdem,
        proofReceiptId: "rcpt_multiparty_x",
        unitType: "DWELL_SECONDS",
        unitCount: "100",
        weight: "1",
        spatialAnchorId: "anchor_x",
        spatialPlacementId: null,
        observedAt: "2027-01-15T00:00:00.000Z",
        status: "ACCEPTED",
      },
    ],
  };
  const mk = (
    partyRole: SettlementSummary["lines"][number]["partyRole"],
    share: string,
    ledgerAccountCode: string,
    amountCents: number,
  ): SettlementSummary["lines"][number] => ({
    idemKey: settlementIdemKey(meterIdem, partyRole, ledgerAccountCode),
    meterRecordIdemKey: meterIdem,
    partyRole,
    share,
    ledgerAccountCode,
    amountCents,
    currency: "GBP",
    status: "PROJECTED",
  });
  const settlement: SettlementSummary = {
    schemaVersion: "settlement.v2",
    orgId: "org_test",
    periodStart: "2027-01-01T00:00:00.000Z",
    periodEnd: "2027-02-01T00:00:00.000Z",
    currency: "GBP",
    meterGross: { [meterIdem]: gross },
    lines: [
      mk("TENANT", "0.700000", "SPATIAL_REVENUE_GROSS", 7001), // residual +1
      mk("VENUE", "0.250000", "SPATIAL_VENUE_PAYOUT", 2500),
      mk("PLATFORM", "0.050000", "SPATIAL_PLATFORM_FEE", 500),
    ],
    totals: { grossCents: 10001, netToTenantCents: 7001, platformFeeCents: 500 },
  };
  return { metering, settlement };
}

describe("verifySettlementReconciliation — exact-cent multi-party split (CRYPTO-04)", () => {
  it("passes for a 3-party split whose residual lands on the largest share", () => {
    const { metering, settlement } = buildMultiPartySplit();
    const report = verifySettlementReconciliation(metering, settlement);
    expect(report.status).toBe("VALID");
  });

  it("flags a 1-cent error on the residual-bearing largest-share line (no ±band)", () => {
    const { metering, settlement } = buildMultiPartySplit();
    settlement.lines[0]!.amountCents = 7000; // was 7001 — drop the residual cent
    const report = verifySettlementReconciliation(metering, settlement);
    expect(report.status).toBe("INVALID");
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_AMOUNT_MISMATCH"),
    ).toBe(true);
  });

  it("flags a 1-cent error on a non-largest line", () => {
    const { metering, settlement } = buildMultiPartySplit();
    settlement.lines[1]!.amountCents = 2499; // was 2500
    const report = verifySettlementReconciliation(metering, settlement);
    expect(report.status).toBe("INVALID");
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_AMOUNT_MISMATCH"),
    ).toBe(true);
  });
});

// ── VER-02: legacy settlement.v1 idemKey (2-field) stays verifiable ───────
//
// Proof packs sealed before the CRYPTO-01 / settlement.v2 3-field idemKey used
// the 2-field `sha256(meterIdemKey|partyRole)`. The auditor must reconstruct
// per the summary's schemaVersion so old packs verify cleanly instead of every
// line flagging SETTLEMENT_IDEM_KEY_MISMATCH.

function buildV1SingleLine(): {
  metering: MeteringSummary;
  settlement: SettlementSummary;
} {
  const meterIdem = "meter_v1_legacy";
  const gross = 5000;
  const metering: MeteringSummary = {
    schemaVersion: "metering.v1",
    orgId: "org_v1",
    periodStart: "2026-01-01T00:00:00.000Z",
    periodEnd: "2026-02-01T00:00:00.000Z",
    records: [
      {
        idemKey: meterIdem,
        proofReceiptId: "rcpt_v1_legacy",
        unitType: "DWELL_SECONDS",
        unitCount: "50",
        weight: "1",
        spatialAnchorId: "anchor_v1",
        spatialPlacementId: null,
        observedAt: "2026-01-15T00:00:00.000Z",
        status: "ACCEPTED",
      },
    ],
  };
  const settlement: SettlementSummary = {
    schemaVersion: "settlement.v1",
    orgId: "org_v1",
    periodStart: "2026-01-01T00:00:00.000Z",
    periodEnd: "2026-02-01T00:00:00.000Z",
    currency: "GBP",
    meterGross: { [meterIdem]: gross },
    lines: [
      {
        // 2-field legacy key — no ledgerAccountCode in the hash domain.
        idemKey: settlementIdemKeyV1(meterIdem, "TENANT"),
        meterRecordIdemKey: meterIdem,
        partyRole: "TENANT",
        share: "1.000000",
        ledgerAccountCode: "SPATIAL_REVENUE_GROSS",
        amountCents: gross,
        currency: "GBP",
        status: "PROJECTED",
      },
    ],
    totals: { grossCents: gross, netToTenantCents: gross, platformFeeCents: 0 },
  };
  return { metering, settlement };
}

describe("verifySettlementReconciliation — legacy settlement.v1 (VER-02)", () => {
  it("verifies a v1 pack's 2-field idemKey as VALID", () => {
    const { metering, settlement } = buildV1SingleLine();
    const report = verifySettlementReconciliation(metering, settlement);
    expect(report.status).toBe("VALID");
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_IDEM_KEY_MISMATCH"),
    ).toBe(false);
  });

  it("still flags a v1 line whose idemKey is wrong", () => {
    const { metering, settlement } = buildV1SingleLine();
    settlement.lines[0]!.idemKey = "0".repeat(64);
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_IDEM_KEY_MISMATCH"),
    ).toBe(true);
  });

  it("rejects a v2 line that uses the old 2-field key (must use 3-field)", () => {
    const { metering, settlement } = buildV1SingleLine();
    settlement.schemaVersion = "settlement.v2"; // now 3-field is required
    const report = verifySettlementReconciliation(metering, settlement);
    expect(
      report.steps.some((s) => s.reason === "SETTLEMENT_IDEM_KEY_MISMATCH"),
    ).toBe(true);
  });
});
