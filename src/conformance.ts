import {
  defineE2EEProviderManifest,
  explainProviderCompatibility,
} from "./provider";
import type {
  E2EEProvider,
  E2EEProviderManifest,
  E2EEProviderRequirements,
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
