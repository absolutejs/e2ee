import { E2EEConfigurationError } from "./errors";
import type { E2EEProviderManifest, E2EERuntime } from "./types";

export const E2EE_CERTIFICATION_CONTRACT = 1 as const;
export const E2EE_CERTIFICATION_SUITE = "absolutejs-e2ee-certification/1";

export type E2EECertificationClaim =
  | "adversarial-lifecycle"
  | "cross-implementation"
  | "independent-audit"
  | "known-answer-vectors"
  | "provider-conformance"
  | "runtime-browser"
  | "runtime-bun"
  | "runtime-node";

export type E2EECertificationImplementation = {
  readonly name: string;
  readonly version: string;
};

export type E2EECertificationVectorEvidence = {
  readonly digestSha256: string;
  readonly sourceUrl: string;
};

export type E2EEAuditScope = {
  readonly packageName: string;
  readonly version: string;
};

export type E2EEIndependentAuditEvidence = {
  readonly auditor: {
    readonly id: string;
    readonly name: string;
  };
  readonly completedAt: string;
  readonly findings: {
    readonly unresolvedCritical: number;
    readonly unresolvedHigh: number;
  };
  readonly reportDigestSha256: string;
  readonly reportUrl: string;
  readonly scope: readonly E2EEAuditScope[];
  readonly validUntil: string;
};

export type E2EECertificationReport = {
  readonly audits?: readonly E2EEIndependentAuditEvidence[];
  readonly claims: readonly E2EECertificationClaim[];
  readonly completedAt: string;
  readonly contract: typeof E2EE_CERTIFICATION_CONTRACT;
  readonly evidenceDigestSha256: string;
  readonly implementations: readonly E2EECertificationImplementation[];
  readonly provider: {
    readonly id: string;
    readonly packageName: E2EEProviderManifest["packageName"];
    readonly version: string;
  };
  readonly runtime: E2EERuntime;
  readonly scenarios: readonly string[];
  readonly suite: typeof E2EE_CERTIFICATION_SUITE;
  readonly vectors: readonly E2EECertificationVectorEvidence[];
};

export type E2EECertificationPolicy = {
  readonly manifest: E2EEProviderManifest;
  readonly maximumAgeMs: number;
  readonly now?: Date;
  readonly requiredClaims: readonly E2EECertificationClaim[];
  readonly runtime: E2EERuntime;
  readonly trustedAuditorIds?: readonly string[];
};

export type E2EECertificationResult = {
  readonly issues: readonly string[];
  readonly passed: boolean;
  readonly report: E2EECertificationReport;
};

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const HTTPS_URL_PATTERN = /^https:\/\//;
const MAXIMUM_CLOCK_SKEW_MS = 300_000;

const unique = (values: readonly string[]) =>
  new Set(values).size === values.length;

const nonEmpty = (value: string) => value.trim().length > 0;

const auditCoversProvider = (
  audit: E2EEIndependentAuditEvidence,
  provider: E2EECertificationReport["provider"],
): boolean =>
  audit.scope.some(
    ({ packageName, version }) =>
      packageName === provider.packageName && version === provider.version,
  );

const auditHasNoBlockingFindings = (
  audit: E2EEIndependentAuditEvidence,
): boolean =>
  audit.findings.unresolvedCritical === 0 &&
  audit.findings.unresolvedHigh === 0;

const freezeReport = (
  report: E2EECertificationReport,
): E2EECertificationReport =>
  Object.freeze({
    ...report,
    ...(report.audits === undefined
      ? {}
      : {
          audits: Object.freeze(
            report.audits.map((audit) =>
              Object.freeze({
                ...audit,
                auditor: Object.freeze({ ...audit.auditor }),
                findings: Object.freeze({ ...audit.findings }),
                scope: Object.freeze(
                  audit.scope.map((entry) => Object.freeze({ ...entry })),
                ),
              }),
            ),
          ),
        }),
    claims: Object.freeze([...report.claims]),
    implementations: Object.freeze(
      report.implementations.map((implementation) =>
        Object.freeze({ ...implementation }),
      ),
    ),
    provider: Object.freeze({ ...report.provider }),
    scenarios: Object.freeze([...report.scenarios]),
    vectors: Object.freeze(
      report.vectors.map((vector) => Object.freeze({ ...vector })),
    ),
  });

export const defineE2EECertificationReport = (
  report: E2EECertificationReport,
): E2EECertificationReport => {
  if (report.contract !== E2EE_CERTIFICATION_CONTRACT)
    throw new E2EEConfigurationError(
      `Unsupported E2EE certification contract ${String(report.contract)}.`,
    );
  if (report.suite !== E2EE_CERTIFICATION_SUITE)
    throw new E2EEConfigurationError("Unsupported E2EE certification suite.");
  if (!nonEmpty(report.provider.id) || !nonEmpty(report.provider.version))
    throw new E2EEConfigurationError(
      "Certification provider identity must be complete.",
    );
  if (!SHA256_PATTERN.test(report.evidenceDigestSha256))
    throw new E2EEConfigurationError(
      "Certification evidence digest must be lowercase SHA-256 hex.",
    );
  if (
    report.claims.length === 0 ||
    !unique(report.claims) ||
    report.scenarios.length === 0 ||
    !unique(report.scenarios)
  )
    throw new E2EEConfigurationError(
      "Certification claims and scenarios must be non-empty and unique.",
    );
  if (!Number.isFinite(Date.parse(report.completedAt)))
    throw new E2EEConfigurationError(
      "Certification completion time must be an ISO timestamp.",
    );
  if (
    report.implementations.some(
      ({ name, version }) => !nonEmpty(name) || !nonEmpty(version),
    ) ||
    !unique(
      report.implementations.map(({ name, version }) => `${name}@${version}`),
    )
  )
    throw new E2EEConfigurationError(
      "Certification implementation identities must be complete and unique.",
    );
  if (
    report.vectors.some(
      ({ digestSha256, sourceUrl }) =>
        !SHA256_PATTERN.test(digestSha256) ||
        !HTTPS_URL_PATTERN.test(sourceUrl),
    )
  )
    throw new E2EEConfigurationError(
      "Certification vectors require an HTTPS source and SHA-256 digest.",
    );
  const audits = report.audits ?? [];
  for (const audit of audits) {
    if (
      !nonEmpty(audit.auditor.id) ||
      !nonEmpty(audit.auditor.name) ||
      audit.auditor.id === report.provider.packageName ||
      !SHA256_PATTERN.test(audit.reportDigestSha256) ||
      !HTTPS_URL_PATTERN.test(audit.reportUrl) ||
      !Number.isFinite(Date.parse(audit.completedAt)) ||
      !Number.isFinite(Date.parse(audit.validUntil)) ||
      Date.parse(audit.validUntil) <= Date.parse(audit.completedAt) ||
      Date.parse(audit.completedAt) >
        Date.parse(report.completedAt) + MAXIMUM_CLOCK_SKEW_MS ||
      audit.scope.length === 0 ||
      !unique(
        audit.scope.map(
          ({ packageName, version }) => `${packageName}@${version}`,
        ),
      ) ||
      audit.scope.some(
        ({ packageName, version }) =>
          !nonEmpty(packageName) || !nonEmpty(version),
      ) ||
      !Number.isSafeInteger(audit.findings.unresolvedCritical) ||
      audit.findings.unresolvedCritical < 0 ||
      !Number.isSafeInteger(audit.findings.unresolvedHigh) ||
      audit.findings.unresolvedHigh < 0
    )
      throw new E2EEConfigurationError(
        "Independent audit evidence is malformed or not release-bound.",
      );
  }
  if (
    report.claims.includes("known-answer-vectors") &&
    report.vectors.length === 0
  )
    throw new E2EEConfigurationError(
      "Known-answer-vector certification requires vector evidence.",
    );
  if (
    report.claims.includes("cross-implementation") &&
    new Set(report.implementations.map(({ name }) => name)).size < 2
  )
    throw new E2EEConfigurationError(
      "Cross-implementation certification requires two distinct implementations.",
    );
  if (
    report.claims.includes("independent-audit") &&
    !audits.some(
      (audit) =>
        auditCoversProvider(audit, report.provider) &&
        auditHasNoBlockingFindings(audit),
    )
  )
    throw new E2EEConfigurationError(
      "Independent-audit certification requires exact provider scope and no unresolved critical or high findings.",
    );

  return freezeReport(report);
};

export const checkE2EECertification = (
  report: E2EECertificationReport,
  policy: E2EECertificationPolicy,
): E2EECertificationResult => {
  const defined = defineE2EECertificationReport(report);
  const issues: string[] = [];
  const now = policy.now ?? new Date();
  const completedAt = new Date(defined.completedAt);
  if (!Number.isSafeInteger(policy.maximumAgeMs) || policy.maximumAgeMs < 1)
    throw new E2EEConfigurationError(
      "Certification maximum age must be a positive safe integer.",
    );
  if (
    defined.provider.id !== policy.manifest.id ||
    defined.provider.packageName !== policy.manifest.packageName ||
    defined.provider.version !== policy.manifest.version
  )
    issues.push("certification is bound to another provider release");
  if (defined.runtime !== policy.runtime)
    issues.push(`certification runtime is not ${policy.runtime}`);
  if (completedAt.getTime() - now.getTime() > MAXIMUM_CLOCK_SKEW_MS)
    issues.push("certification completion time is in the future");
  if (now.getTime() - completedAt.getTime() > policy.maximumAgeMs)
    issues.push("certification is stale");
  for (const claim of policy.requiredClaims)
    if (!defined.claims.includes(claim))
      issues.push(`certification claim ${claim} is missing`);
  if (policy.requiredClaims.includes("independent-audit")) {
    const currentAudits = (defined.audits ?? []).filter(
      (audit) =>
        auditCoversProvider(audit, defined.provider) &&
        auditHasNoBlockingFindings(audit) &&
        new Date(audit.validUntil).getTime() >= now.getTime(),
    );
    if (currentAudits.length === 0)
      issues.push("independent audit evidence is expired or out of scope");
    else if (
      policy.trustedAuditorIds !== undefined &&
      !currentAudits.some((audit) =>
        policy.trustedAuditorIds!.includes(audit.auditor.id),
      )
    )
      issues.push("independent audit is not from a trusted auditor");
  }

  return Object.freeze({
    issues: Object.freeze(issues),
    passed: issues.length === 0,
    report: defined,
  });
};
