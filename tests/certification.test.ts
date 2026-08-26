import { describe, expect, test } from "bun:test";
import {
  checkE2EECertification,
  defineE2EECertificationReport,
  defineE2EEProviderManifest,
  type E2EECertificationReport,
} from "../src";

const now = new Date("2026-08-26T12:00:00.000Z");
const manifest = defineE2EEProviderManifest({
  contract: 1,
  costModel: "free",
  description: "Certification fixture",
  id: "fixture",
  packageName: "@absolutejs/e2ee-fixture",
  protocols: ["MLS-1.0"],
  roles: ["messaging"],
  runtimes: ["bun"],
  security: {
    assurance: "experimental",
    forwardSecrecy: true,
    operatorCanDecrypt: false,
    postCompromiseSecurity: true,
    postQuantum: false,
    privateKeyProtection: "non-exportable",
    supportedModes: ["strict-e2ee"],
  },
  version: "0.1.0",
});
const report = (
  overrides: Partial<E2EECertificationReport> = {},
): E2EECertificationReport => ({
  claims: ["provider-conformance", "adversarial-lifecycle", "runtime-bun"],
  completedAt: now.toISOString(),
  contract: 1,
  evidenceDigestSha256: "a".repeat(64),
  implementations: [{ name: "fixture-engine", version: "1.0.0" }],
  provider: {
    id: manifest.id,
    packageName: manifest.packageName,
    version: manifest.version,
  },
  runtime: "bun",
  scenarios: ["manifest", "welcome-replay", "state-rollback"],
  suite: "absolutejs-e2ee-certification/1",
  vectors: [],
  ...overrides,
});

describe("E2EE provider certification", () => {
  test("accepts and freezes exact fresh provider-release evidence", () => {
    const result = checkE2EECertification(report(), {
      manifest,
      maximumAgeMs: 86_400_000,
      now,
      requiredClaims: ["provider-conformance", "adversarial-lifecycle"],
      runtime: "bun",
    });

    expect(result.passed).toBe(true);
    expect(Object.isFrozen(result.report)).toBe(true);
    expect(Object.isFrozen(result.report.implementations)).toBe(true);
  });

  test("fails closed for another release, stale evidence, and missing claims", () => {
    const result = checkE2EECertification(
      report({
        claims: ["provider-conformance"],
        completedAt: "2026-08-20T12:00:00.000Z",
        provider: { ...report().provider, version: "0.0.9" },
      }),
      {
        manifest,
        maximumAgeMs: 86_400_000,
        now,
        requiredClaims: ["cross-implementation"],
        runtime: "bun",
      },
    );

    expect(result.passed).toBe(false);
    expect(result.issues).toEqual([
      "certification is bound to another provider release",
      "certification is stale",
      "certification claim cross-implementation is missing",
    ]);
  });

  test("does not allow vector or interoperability claims without evidence", () => {
    expect(() =>
      defineE2EECertificationReport(
        report({ claims: ["known-answer-vectors"] }),
      ),
    ).toThrow("requires vector evidence");
    expect(() =>
      defineE2EECertificationReport(
        report({ claims: ["cross-implementation"] }),
      ),
    ).toThrow("requires two distinct implementations");
  });

  test("requires release-bound independent audit evidence", () => {
    expect(() =>
      defineE2EECertificationReport(report({ claims: ["independent-audit"] })),
    ).toThrow("exact provider scope");
    expect(() =>
      defineE2EECertificationReport(
        report({
          audits: [
            {
              auditor: { id: "security-lab", name: "Security Lab" },
              completedAt: "2026-08-25T12:00:00.000Z",
              findings: { unresolvedCritical: 0, unresolvedHigh: 1 },
              reportDigestSha256: "b".repeat(64),
              reportUrl: "https://example.com/audit.pdf",
              scope: [
                {
                  packageName: manifest.packageName,
                  version: manifest.version,
                },
              ],
              validUntil: "2027-08-25T12:00:00.000Z",
            },
          ],
          claims: ["independent-audit"],
        }),
      ),
    ).toThrow("no unresolved critical or high findings");
  });

  test("checks audit expiry and the deployment auditor allowlist", () => {
    const audited = report({
      audits: [
        {
          auditor: { id: "security-lab", name: "Security Lab" },
          completedAt: "2026-08-25T12:00:00.000Z",
          findings: { unresolvedCritical: 0, unresolvedHigh: 0 },
          reportDigestSha256: "b".repeat(64),
          reportUrl: "https://example.com/audit.pdf",
          scope: [
            {
              packageName: manifest.packageName,
              version: manifest.version,
            },
            { packageName: "ts-mls", version: "2.0.0-rc.16" },
          ],
          validUntil: "2026-09-25T12:00:00.000Z",
        },
      ],
      claims: ["independent-audit"],
    });
    const allowed = checkE2EECertification(audited, {
      manifest,
      maximumAgeMs: 86_400_000,
      now,
      requiredClaims: ["independent-audit"],
      runtime: "bun",
      trustedAuditorIds: ["security-lab"],
    });
    const untrusted = checkE2EECertification(audited, {
      manifest,
      maximumAgeMs: 86_400_000,
      now,
      requiredClaims: ["independent-audit"],
      runtime: "bun",
      trustedAuditorIds: ["another-lab"],
    });

    expect(allowed.passed).toBe(true);
    expect(Object.isFrozen(allowed.report.audits?.[0]?.scope)).toBe(true);
    expect(untrusted.passed).toBe(false);
    expect(untrusted.issues).toContain(
      "independent audit is not from a trusted auditor",
    );
  });
});
