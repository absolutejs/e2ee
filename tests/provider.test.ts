import { describe, expect, test } from "bun:test";
import {
  E2EEConfigurationError,
  E2EEProviderSelectionError,
  defineE2EEProviderManifest,
  explainProviderCompatibility,
  selectE2EEProvider,
  type AssuranceLevel,
  type E2EEProvider,
  type E2EEProviderManifest,
} from "../src";

const createManifest = (
  id: string,
  assurance: AssuranceLevel = "reviewed",
): E2EEProviderManifest =>
  defineE2EEProviderManifest({
    contract: 1,
    costModel: "free",
    description: `${id} test provider`,
    id,
    packageName: `@absolutejs/e2ee-${id}`,
    protocols: ["MLS-1.0"],
    roles: ["messaging"],
    runtimes: ["browser", "bun"],
    security: {
      assurance,
      auditUrls:
        assurance === "audited" ? ["https://example.com/audit"] : undefined,
      forwardSecrecy: true,
      operatorCanDecrypt: false,
      postCompromiseSecurity: true,
      postQuantum: false,
      privateKeyProtection: "non-exportable",
      supportedModes: ["strict-e2ee", "managed-recovery"],
    },
    version: "0.1.0",
  });

const requirements = {
  minimumAssurance: "reviewed" as const,
  operatorCanDecrypt: false,
  protocols: ["MLS-1.0"],
  requireForwardSecrecy: true,
  requirePostCompromiseSecurity: true,
  roles: ["messaging"] as const,
  runtime: "browser" as const,
  securityMode: "strict-e2ee" as const,
};

describe("provider manifests", () => {
  test("validates and deeply freezes security claims", () => {
    const manifest = createManifest("fixture");

    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(manifest.protocols)).toBe(true);
    expect(Object.isFrozen(manifest.security)).toBe(true);
    expect(Object.isFrozen(manifest.security.supportedModes)).toBe(true);
  });

  test("rejects a decrypting operator claiming strict E2EE", () => {
    const unsafe = createManifest("unsafe");
    expect(() =>
      defineE2EEProviderManifest({
        ...unsafe,
        security: { ...unsafe.security, operatorCanDecrypt: true },
      }),
    ).toThrow(E2EEConfigurationError);
  });

  test("requires evidence for audited assurance", () => {
    const reviewed = createManifest("reviewed");
    expect(() =>
      defineE2EEProviderManifest({
        ...reviewed,
        security: {
          ...reviewed.security,
          assurance: "audited",
          auditUrls: undefined,
        },
      }),
    ).toThrow("must publish at least one audit URL");
  });
});

describe("provider selection", () => {
  test("selects the highest-assurance compatible provider", () => {
    const providers: E2EEProvider[] = [
      { manifest: createManifest("reviewed") },
      { manifest: createManifest("audited", "audited") },
    ];

    expect(selectE2EEProvider(providers, requirements).manifest.id).toBe(
      "audited",
    );
  });

  test("fails closed with reasons for every rejected provider", () => {
    const provider = { manifest: createManifest("fixture") };

    expect(() =>
      selectE2EEProvider([provider], {
        ...requirements,
        protocols: ["unavailable"],
        runtime: "capacitor-ios",
      }),
    ).toThrow(E2EEProviderSelectionError);

    const result = explainProviderCompatibility(provider.manifest, {
      ...requirements,
      protocols: ["unavailable"],
      runtime: "capacitor-ios",
    });
    expect(result.compatible).toBe(false);
    expect(result.reasons).toContain("runtime capacitor-ios is not supported");
    expect(result.reasons).toContain("protocol unavailable is missing");
  });

  test("requires an explicit policy opt-in for post-quantum claims", () => {
    const reviewed = createManifest("pq");
    const postQuantum = defineE2EEProviderManifest({
      ...reviewed,
      security: { ...reviewed.security, postQuantum: true },
    });

    expect(
      explainProviderCompatibility(postQuantum, requirements).reasons,
    ).toContain("post-quantum claim was not explicitly allowed by policy");
  });
});
