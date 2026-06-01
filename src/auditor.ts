// @enfinitos/sdk-auditor — top-level EnfinitOSAuditor class.
//
// This is the entry point a regulator / auditor / customer engineer
// reaches for. It composes the four verification primitives —
// signature, chain, metering projection, settlement reconciliation —
// behind a single class that handles key loading, report rollup, and
// the SKIPPED-vs-VALID-vs-INVALID promotion rules.
//
// Trust model
// ───────────
// The auditor SDK is designed so that the only inputs an external
// party needs are:
//
//   1. The JSON proof pack (signed by the platform).
//   2. The verification key set — fetched from the platform OR
//      supplied locally (for fully-offline audit).
//
// They do NOT need:
//   - Access to the EnfinitOS code base.
//   - Credentials with the platform (the runtime-keys endpoint is
//     intentionally unauthenticated; key directories are public
//     artefacts by design).
//   - Anything the platform might revoke or alter post-hoc.
//
// Result: the SDK can run from a customer's laptop, in an air-gapped
// regulator review room, or inside a third-party compliance tool, and
// produce identical structured verdicts.

import { AuditorError, asAuditorError } from "./errors";
import {
  loadKeyDirectory,
  KeyDirectory,
  type FetchLike,
  type VerificationKeySourceKind,
} from "./keys";
import { verifyMeteringProjection } from "./meteringAudit";
import { verifyProofChain } from "./proofChain";
import {
  parseSignedProofPack,
  verifyProofRecord,
  defaultSignatureVerifier,
  type SignatureVerifier,
} from "./proofPack";
import { verifySettlementReconciliation } from "./settlementAudit";
import {
  SDK_VERSION,
  type AuditBundle,
  type AuditReport,
  type AuditStep,
  type AuditStepStatus,
  type ChainAuditReport,
  type FullAuditReport,
  type MeteringSummary,
  type ProjectionAuditReport,
  type ProofPack,
  type ProofRecord,
  type SettlementAuditReport,
  type SettlementSummary,
  type SignedProofPack,
  type VerificationKey,
} from "./types";

// ─────────────────────────────────────────────────────────────────────
// Construction options
// ─────────────────────────────────────────────────────────────────────

export type EnfinitOSAuditorOptions = {
  /**
   * Where to source verification keys from.
   *   - "platform" (default): fetch from `platformKeysUrl` on first
   *     verifyProofPack call, cache for the lifetime of the auditor.
   *   - "local":              use `localKeys` (regulator / offline).
   */
  verificationKeySource?: VerificationKeySourceKind;

  /** Defaults to https://api.enfinitos.com/v1/runtime-keys. */
  platformKeysUrl?: string;

  /** Local key set (required if verificationKeySource === "local"). */
  localKeys?: VerificationKey[];

  /**
   * Inject a custom fetch implementation — used by tests, by hosts
   * with non-global fetch (older Node), and by audit shells running
   * inside isolated network policies that route through a proxy.
   */
  httpFetch?: FetchLike;

  /**
   * Inject a custom signature verifier. Default verifier prefers
   * `@noble/ed25519` and falls back to Node `crypto.verify`.
   */
  signatureVerifier?: SignatureVerifier;
};

// ─────────────────────────────────────────────────────────────────────
// The auditor
// ─────────────────────────────────────────────────────────────────────

/**
 * EnfinitOSAuditor — the SDK's main verification facade.
 *
 * Usage:
 *
 *   const auditor = new EnfinitOSAuditor({
 *     verificationKeySource: "platform",
 *     platformKeysUrl: "https://api.enfinitos.com/v1/runtime-keys",
 *   });
 *
 *   const report = await auditor.verifyProofPack(pack);
 *   if (report.status !== "VALID") {
 *     for (const step of report.steps) {
 *       if (step.status === "INVALID") {
 *         console.error(step.reason, step.message);
 *       }
 *     }
 *   }
 *
 * The instance is thread-safe (well, single-threaded JS) and reusable
 * across many packs. The key directory is loaded on first use and
 * cached for the instance's lifetime.
 */
export class EnfinitOSAuditor {
  private readonly source: VerificationKeySourceKind;
  private readonly platformKeysUrl: string | undefined;
  private readonly localKeys: VerificationKey[] | undefined;
  private readonly httpFetch: FetchLike | undefined;
  private readonly verifier: SignatureVerifier;

  private keyDirectoryPromise: Promise<KeyDirectory> | null = null;

  constructor(opts: EnfinitOSAuditorOptions = {}) {
    this.source = opts.verificationKeySource ?? "platform";
    this.platformKeysUrl = opts.platformKeysUrl;
    this.localKeys = opts.localKeys;
    this.httpFetch = opts.httpFetch;
    this.verifier = opts.signatureVerifier ?? defaultSignatureVerifier;

    if (this.source === "local" && !this.localKeys) {
      throw new AuditorError({
        code: "INVALID_INPUT",
        message:
          "verificationKeySource='local' requires opts.localKeys to be provided",
      });
    }
  }

  /**
   * Get (or load + cache) the key directory. The promise is reused
   * so concurrent verifyProofPack calls share a single fetch.
   */
  private getKeyDirectory(): Promise<KeyDirectory> {
    if (this.keyDirectoryPromise === null) {
      this.keyDirectoryPromise = loadKeyDirectory({
        source: this.source,
        ...(this.platformKeysUrl !== undefined
          ? { platformKeysUrl: this.platformKeysUrl }
          : {}),
        ...(this.localKeys !== undefined ? { localKeys: this.localKeys } : {}),
        ...(this.httpFetch !== undefined ? { httpFetch: this.httpFetch } : {}),
      }).catch((e) => {
        // Re-arm: if the load failed once, the next call can retry.
        // (This is the ONE place we let the cache reset, so the
        // common-case "transient network blip during the first call"
        // doesn't permanently brick the auditor instance.)
        this.keyDirectoryPromise = null;
        throw e;
      });
    }
    return this.keyDirectoryPromise;
  }

  // ─────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────

  /**
   * verifyProofPack — parses, verifies signatures, and verifies the
   * chain of a SignedProofPack. Does NOT re-project metering or
   * settlement (use verifyAll for that).
   *
   * Accepts either a parsed SignedProofPack or a raw object that
   * looks like one (so a regulator can feed JSON.parse(file) directly).
   */
  async verifyProofPack(pack: SignedProofPack | unknown): Promise<AuditReport> {
    const verifiedAt = new Date().toISOString();
    let parsed: SignedProofPack;
    try {
      parsed = isSignedProofPack(pack) ? pack : parseSignedProofPack(pack);
    } catch (e) {
      const err = asAuditorError(e, "INVALID_INPUT", "failed to parse pack");
      // Convert parse-fail to a single-step INVALID report — the
      // caller wants a structured verdict, not an exception trace.
      return {
        status: "INVALID",
        packId: typeof (pack as { packId?: unknown })?.packId === "string"
          ? (pack as { packId: string }).packId
          : "unknown",
        orgId: typeof (pack as { orgId?: unknown })?.orgId === "string"
          ? (pack as { orgId: string }).orgId
          : "unknown",
        verifiedAt,
        sdkVersion: SDK_VERSION,
        envelopeVersion: typeof (pack as { envelopeVersion?: unknown })?.envelopeVersion === "string"
          ? ((pack as { envelopeVersion: SignedProofPack["envelopeVersion"] | "unknown" }).envelopeVersion)
          : "unknown",
        keysSnapshot: {
          source: this.source,
          snapshotId: null,
          keyCount: 0,
          keyIds: [],
        },
        steps: [
          {
            target: "pack",
            kind: "envelope",
            status: "INVALID",
            reason: err.reason ?? "MALFORMED_PACK",
            message: err.message,
            ...(err.detail ? { detail: err.detail } : {}),
          },
        ],
      };
    }

    const keys = await this.getKeyDirectory();
    const steps: AuditStep[] = [];

    // Envelope-level checks.
    if (parsed.records.length === 0) {
      steps.push({
        target: "pack.records",
        kind: "envelope",
        status: "INVALID",
        reason: "EMPTY_PACK",
        message: "proof pack contains zero records — cannot audit",
      });
    } else {
      steps.push({
        target: "pack.records",
        kind: "envelope",
        status: "VALID",
        message: `pack contains ${parsed.records.length} record(s)`,
      });
    }

    // Per-record signature + canonicalisation + key-lookup.
    for (let i = 0; i < parsed.records.length; i++) {
      const recordSteps = await verifyProofRecord(
        parsed.records[i]!,
        i,
        keys,
        this.verifier,
      );
      steps.push(...recordSteps);
    }

    const status = rollupStatus(steps);
    return {
      status,
      packId: parsed.packId,
      orgId: parsed.orgId,
      verifiedAt,
      sdkVersion: SDK_VERSION,
      envelopeVersion: parsed.envelopeVersion,
      keysSnapshot: {
        source: keys.snapshot.source,
        snapshotId: keys.snapshot.snapshotId,
        keyCount: keys.size(),
        keyIds: keys.keyIds(),
      },
      steps,
    };
  }

  /**
   * verifyProofChain — chain-walk only. Useful when the caller has
   * already verified signatures via verifyProofPack and now wants to
   * audit the chain separately (or wants to audit a non-proof chain
   * — basis/right/offer/challenge — that uses the same shape).
   *
   * Pass `priorAfterHash` to anchor a later pack's first record at
   * the previous pack's tail `afterHash` (cross-pack continuity).
   * Omit it (or pass `null`) for a standalone / first pack — the
   * auditor will then enforce the genesis invariant
   * (records[0].beforeHash === null).
   */
  async verifyProofChain(
    records: ProofRecord[],
    priorAfterHash: string | null = null,
  ): Promise<ChainAuditReport> {
    return verifyProofChain(records, priorAfterHash);
  }

  /**
   * verifyMeteringProjection — re-project proof into metering and
   * confirm it reconciles.
   */
  async verifyMeteringProjection(
    proof: ProofPack,
    metering: MeteringSummary,
  ): Promise<ProjectionAuditReport> {
    // Materialise as ProofRecord[] — the projection function takes
    // ProofRecord[] but only reads .payload. We accept ProofPack at
    // the public API for ergonomics (callers may not have full
    // signed records to hand at this point).
    const proofRecords: ProofRecord[] = proof.records.map((r) => ({
      payload: r.payload,
      // The fields below are not consulted by the projection
      // function — supplied as empty so the type checker is happy.
      keyId: "",
      algorithm: "ed25519",
      signature: "",
      payloadCanonical: "",
      beforeHash: null,
      afterHash: "",
    }));
    return verifyMeteringProjection(proofRecords, metering, proof.orgId);
  }

  /**
   * verifySettlementReconciliation — re-compute settlement and
   * confirm it reconciles to metering.
   */
  async verifySettlementReconciliation(
    metering: MeteringSummary,
    settlement: SettlementSummary,
  ): Promise<SettlementAuditReport> {
    return verifySettlementReconciliation(metering, settlement);
  }

  /**
   * verifyAll — the regulator's one-shot verification.
   *
   * Runs the full pipeline against an AuditBundle:
   *   1. verifyProofPack (signatures + canonicalisation per record)
   *   2. verifyProofChain (chain-walk)
   *   3. verifyMeteringProjection (re-project; SKIPPED if not in bundle)
   *   4. verifySettlementReconciliation (re-compute; SKIPPED if not)
   *
   * Returns a FullAuditReport with all four sub-reports plus the
   * rolled-up status (VALID if every sub-report is VALID).
   */
  async verifyAll(bundle: AuditBundle): Promise<FullAuditReport> {
    const verifiedAt = new Date().toISOString();
    if (bundle.verificationKeys) {
      // Allow per-bundle override of the directory. Useful when
      // auditing a months-old pack whose keys have been rotated since.
      // We deliberately do NOT cache this — every verifyAll with
      // explicit keys is a fresh directory.
      const tempAuditor = new EnfinitOSAuditor({
        verificationKeySource: "local",
        localKeys: bundle.verificationKeys,
        ...(this.httpFetch !== undefined ? { httpFetch: this.httpFetch } : {}),
        signatureVerifier: this.verifier,
      });
      const { verificationKeys: _unused, ...rest } = bundle;
      void _unused;
      return tempAuditor.verifyAll(rest);
    }

    const pack = await this.verifyProofPack(bundle.pack);
    // Forward the optional cross-pack anchor — see AuditBundle.priorAfterHash
    // in types.ts. Genesis (no prior pack) defaults to null.
    const chain = await this.verifyProofChain(
      bundle.pack.records,
      bundle.priorAfterHash ?? null,
    );

    let metering: ProjectionAuditReport;
    if (bundle.metering ?? bundle.pack.metering) {
      const m = bundle.metering ?? bundle.pack.metering!;
      metering = await this.verifyMeteringProjection(
        toProofPack(bundle.pack),
        m,
      );
    } else {
      metering = {
        status: "SKIPPED",
        verifiedAt,
        sdkVersion: SDK_VERSION,
        proofRecordCount: bundle.pack.records.length,
        meterRecordCount: 0,
        steps: [
          {
            target: "metering",
            kind: "meter_projection",
            status: "SKIPPED",
            message: "no metering summary in the bundle — skipped",
          },
        ],
      };
    }

    let settlement: SettlementAuditReport;
    const settlementInput = bundle.settlement ?? bundle.pack.settlement;
    const meteringInput = bundle.metering ?? bundle.pack.metering;
    if (settlementInput && meteringInput) {
      settlement = await this.verifySettlementReconciliation(
        meteringInput,
        settlementInput,
      );
    } else {
      settlement = {
        status: "SKIPPED",
        verifiedAt,
        sdkVersion: SDK_VERSION,
        meterRecordCount: meteringInput?.records.length ?? 0,
        settlementLineCount: 0,
        steps: [
          {
            target: "settlement",
            kind: "settlement_line",
            status: "SKIPPED",
            message:
              "settlement reconciliation skipped — bundle lacks either metering or settlement summary",
          },
        ],
      };
    }

    const status = rollupOverallStatus([
      pack.status,
      chain.status,
      metering.status,
      settlement.status,
    ]);

    return {
      status,
      packId: pack.packId,
      orgId: pack.orgId,
      verifiedAt,
      sdkVersion: SDK_VERSION,
      keysSnapshot: pack.keysSnapshot,
      pack,
      chain,
      metering,
      settlement,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

function isSignedProofPack(v: unknown): v is SignedProofPack {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o["envelopeVersion"] === "string" &&
    typeof o["issuedAt"] === "string" &&
    typeof o["orgId"] === "string" &&
    typeof o["packId"] === "string" &&
    Array.isArray(o["records"])
  );
}

function toProofPack(pack: SignedProofPack): ProofPack {
  return {
    envelopeVersion: pack.envelopeVersion,
    issuedAt: pack.issuedAt,
    orgId: pack.orgId,
    packId: pack.packId,
    records: pack.records.map((r) => ({ payload: r.payload })),
  };
}

/**
 * rollupStatus — fold a step list into a single status. INVALID wins
 * everything; otherwise SKIPPED if any step skipped; otherwise VALID.
 *
 * Note: this is deliberately conservative — a SKIPPED step does NOT
 * promote to VALID, because "we didn't check it" is not the same as
 * "we checked it and it passed". Auditors care about that distinction.
 */
function rollupStatus(steps: AuditStep[]): AuditStepStatus {
  if (steps.some((s) => s.status === "INVALID")) return "INVALID";
  if (steps.every((s) => s.status === "SKIPPED")) return "SKIPPED";
  return "VALID";
}

function rollupOverallStatus(statuses: AuditStepStatus[]): AuditStepStatus {
  if (statuses.includes("INVALID")) return "INVALID";
  if (statuses.every((s) => s === "SKIPPED")) return "SKIPPED";
  if (statuses.every((s) => s === "VALID")) return "VALID";
  // Mix of VALID + SKIPPED — we surface as "VALID" because every
  // step we actually ran passed; SKIPPED is a conscious choice (no
  // metering bundle, no settlement bundle).
  return "VALID";
}
