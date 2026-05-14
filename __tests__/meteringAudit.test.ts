import { describe, expect, it } from "vitest";

import { verifyMeteringProjection } from "../src/meteringAudit.js";

import {
  buildMeteringSummary,
  buildMultiRecordChain,
  generateKey,
} from "./fixtures/builder.js";

describe("verifyMeteringProjection", () => {
  it("passes when metering re-projects exactly from proof", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(4, key);
    const metering = buildMeteringSummary(pack);
    const report = verifyMeteringProjection(pack.records, metering, pack.orgId);
    expect(report.status).toBe("VALID");
    expect(report.meterRecordCount).toBe(4);
  });

  it("flags METER_RECORD_FOR_UNKNOWN_PROOF when proofReceiptId is missing", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    metering.records[0]!.proofReceiptId = "ghost_id";
    const report = verifyMeteringProjection(pack.records, metering, pack.orgId);
    expect(report.status).toBe("INVALID");
    expect(
      report.steps.some((s) => s.reason === "METER_RECORD_FOR_UNKNOWN_PROOF"),
    ).toBe(true);
  });

  it("flags METER_IDEM_KEY_MISMATCH when idemKey is wrong", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    metering.records[0]!.idemKey = "0".repeat(64);
    const report = verifyMeteringProjection(pack.records, metering, pack.orgId);
    expect(
      report.steps.some((s) => s.reason === "METER_IDEM_KEY_MISMATCH"),
    ).toBe(true);
  });

  it("flags METER_UNIT_COUNT_MISMATCH when unitCount is wrong", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    metering.records[0]!.unitCount = "9999.999999";
    const report = verifyMeteringProjection(pack.records, metering, pack.orgId);
    expect(
      report.steps.some((s) => s.reason === "METER_UNIT_COUNT_MISMATCH"),
    ).toBe(true);
  });

  it("flags METER_ORG_MISMATCH when summary.orgId differs from pack orgId", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    metering.orgId = "org_different";
    const report = verifyMeteringProjection(pack.records, metering, pack.orgId);
    expect(report.steps.some((s) => s.reason === "METER_ORG_MISMATCH")).toBe(true);
  });

  it("flags METER_TOTAL_MISMATCH when totals are wrong", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    metering.totals!.DWELL_SECONDS = "0.000001";
    const report = verifyMeteringProjection(pack.records, metering, pack.orgId);
    expect(
      report.steps.some((s) => s.reason === "METER_TOTAL_MISMATCH"),
    ).toBe(true);
  });
});
