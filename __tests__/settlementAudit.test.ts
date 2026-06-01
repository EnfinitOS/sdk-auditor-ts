import { describe, expect, it } from "vitest";

import { verifySettlementReconciliation } from "../src/settlementAudit.js";

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
