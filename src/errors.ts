// @enfinitos/sdk-auditor — typed error envelope.
//
// The auditor SDK distinguishes two kinds of failures:
//
//   1. **Audit failures**     — the artefact under audit fails one
//                               of the verification steps. These are
//                               NOT thrown; they are recorded as
//                               INVALID steps inside the AuditReport.
//                               This is the normal case: an auditor
//                               who runs the SDK on a tampered pack
//                               wants a structured report, not an
//                               exception trace.
//
//   2. **Operational errors** — the SDK itself cannot run (e.g. the
//                               key-directory endpoint is down, the
//                               input JSON is malformed enough that
//                               we can't even decide it's a pack).
//                               These ARE thrown as AuditorError so
//                               the caller can distinguish a "can't
//                               verify" from a "verified-and-failed".
//
// The line between (1) and (2) is "did we get far enough to produce a
// useful structured verdict?". If yes, it's an audit failure and we
// stay inside the report. If no, it's an operational error and we
// throw.

import type { AuditReasonCode } from "./types";

/**
 * AuditorError — thrown only for operational failures the SDK could
 * not reduce to a structured AuditReport step.
 *
 * Carries:
 *   - `code`: machine-readable enum for caller dispatch
 *   - `reason`: optional reason code for callers that want to
 *     surface it like a normal audit step (e.g. CLI shells)
 *   - `cause`: the original Error / unknown, for diagnostics
 *
 * Note: `cause` is a standard ES2022 Error field but we re-state it
 * here typed as `unknown` so consumers can downcast safely.
 */
export class AuditorError extends Error {
  readonly code: AuditorErrorCode;
  readonly reason: AuditReasonCode | null;
  readonly detail: Record<string, unknown> | null;
  override readonly cause: unknown;

  constructor(opts: {
    code: AuditorErrorCode;
    message: string;
    reason?: AuditReasonCode;
    detail?: Record<string, unknown>;
    cause?: unknown;
  }) {
    super(opts.message);
    this.name = "AuditorError";
    this.code = opts.code;
    this.reason = opts.reason ?? null;
    this.detail = opts.detail ?? null;
    this.cause = opts.cause;
    // Maintain prototype chain for instanceof through transpilation
    Object.setPrototypeOf(this, AuditorError.prototype);
  }
}

/**
 * AuditorErrorCode — the distinct operational failure modes.
 *
 *   - INVALID_INPUT:       a function received an argument that
 *                          fails type-shape validation _before_ any
 *                          verification work could run.
 *   - KEYS_UNAVAILABLE:    we can't reach the key-directory and the
 *                          caller did not supply local keys.
 *   - KEYS_MALFORMED:      the key-directory returned a body we
 *                          can't parse.
 *   - PLATFORM_RESPONSE:   the key-directory returned an HTTP error
 *                          (non-2xx).
 *   - INTERNAL:            an invariant failed inside the SDK. This
 *                          should never reach a regulator — file a
 *                          bug.
 */
export type AuditorErrorCode =
  | "INVALID_INPUT"
  | "KEYS_UNAVAILABLE"
  | "KEYS_MALFORMED"
  | "PLATFORM_RESPONSE"
  | "INTERNAL";

/**
 * Helper: wrap an unknown thrown value into an AuditorError with a
 * stable code. Used at every async boundary where a generic fetch /
 * crypto call might throw something we did not anticipate.
 */
export function asAuditorError(
  e: unknown,
  fallbackCode: AuditorErrorCode,
  fallbackMessage: string,
): AuditorError {
  if (e instanceof AuditorError) {
    return e;
  }
  return new AuditorError({
    code: fallbackCode,
    message: e instanceof Error ? e.message : fallbackMessage,
    cause: e,
  });
}
