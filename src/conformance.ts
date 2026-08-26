import {
  defineE2EEProviderManifest,
  explainProviderCompatibility,
} from "./provider";
import type {
  E2EEProvider,
  E2EEProviderManifest,
  E2EEProviderRequirements,
  MessagingProvider,
} from "./types";

export type ProviderConformanceOptions = {
  readonly createProvider: () => E2EEProvider | Promise<E2EEProvider>;
  readonly validRequirement: E2EEProviderRequirements;
};

export type ProviderConformanceResult = {
  readonly issues: readonly string[];
  readonly manifest?: E2EEProviderManifest;
  readonly passed: boolean;
};

export type MessagingProviderConformanceOptions = {
  readonly createProvider: () => MessagingProvider | Promise<MessagingProvider>;
};

/**
 * Runs test-runner-neutral checks shared by every E2EE provider package.
 * Provider test suites should fail when `passed` is false and print `issues`.
 */
export const checkE2EEProviderConformance = async (
  options: ProviderConformanceOptions,
): Promise<ProviderConformanceResult> => {
  const issues: string[] = [];
  let provider: E2EEProvider;
  let manifest: E2EEProviderManifest | undefined;

  try {
    provider = await options.createProvider();
  } catch {
    return Object.freeze({
      issues: Object.freeze(["provider creation failed"]),
      passed: false,
    });
  }

  try {
    manifest = defineE2EEProviderManifest(provider.manifest);
  } catch (error) {
    issues.push(
      error instanceof Error
        ? `manifest validation failed: ${error.message}`
        : "manifest validation failed",
    );
  }

  if (manifest !== undefined) {
    const compatibility = explainProviderCompatibility(
      manifest,
      options.validRequirement,
    );
    if (!compatibility.compatible) {
      issues.push(
        `declared supported requirement was rejected: ${compatibility.reasons.join(", ")}`,
      );
    }
  }

  return Object.freeze({
    issues: Object.freeze(issues),
    manifest,
    passed: issues.length === 0,
  });
};

export const checkMessagingProviderConformance = async (
  options: MessagingProviderConformanceOptions,
): Promise<ProviderConformanceResult> => {
  const result = await checkE2EEProviderConformance({
    createProvider: options.createProvider,
    validRequirement: {
      minimumAssurance: "experimental",
      operatorCanDecrypt: false,
      protocols: ["MLS-1.0"],
      requireForwardSecrecy: true,
      requirePostCompromiseSecurity: true,
      roles: ["messaging"],
      runtime: "bun",
      securityMode: "strict-e2ee",
    },
  });
  const issues = [...result.issues];
  const manifest = result.manifest;

  if (manifest !== undefined) {
    if (!manifest.protocols.includes("MLS-1.0")) {
      issues.push("messaging provider does not declare MLS-1.0");
    }
    if (!manifest.security.forwardSecrecy) {
      issues.push("messaging provider does not declare forward secrecy");
    }
    if (!manifest.security.postCompromiseSecurity) {
      issues.push(
        "messaging provider does not declare post-compromise security",
      );
    }
  }

  return Object.freeze({
    issues: Object.freeze(issues),
    manifest,
    passed: issues.length === 0,
  });
};
