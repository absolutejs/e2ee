import {
  E2EE_PROVIDER_CONTRACT,
  type AssuranceLevel,
  type E2EEProvider,
  type E2EEProviderManifest,
  type E2EEProviderRequirements,
  type ProviderCompatibility,
} from "./types";
import { E2EEConfigurationError, E2EEProviderSelectionError } from "./errors";

const assuranceRank: Readonly<Record<AssuranceLevel, number>> = {
  experimental: 0,
  reviewed: 1,
  audited: 2,
};

const packagePattern = /^@absolutejs\/e2ee-[a-z0-9]+(?:-[a-z0-9]+)*$/;

const unique = <Value extends string>(values: readonly Value[]): boolean =>
  new Set(values).size === values.length;

const nonEmpty = (value: string): boolean => value.trim().length > 0;

const freezeManifest = (manifest: E2EEProviderManifest): E2EEProviderManifest =>
  Object.freeze({
    ...manifest,
    protocols: Object.freeze([...manifest.protocols]),
    roles: Object.freeze([...manifest.roles]),
    runtimes: Object.freeze([...manifest.runtimes]),
    security: Object.freeze({
      ...manifest.security,
      auditUrls:
        manifest.security.auditUrls === undefined
          ? undefined
          : Object.freeze([...manifest.security.auditUrls]),
      supportedModes: Object.freeze([...manifest.security.supportedModes]),
    }),
  });

export const defineE2EEProviderManifest = (
  manifest: E2EEProviderManifest,
): E2EEProviderManifest => {
  if (manifest.contract !== E2EE_PROVIDER_CONTRACT) {
    throw new E2EEConfigurationError(
      `Unsupported E2EE provider contract ${String(manifest.contract)}.`,
    );
  }
  if (!nonEmpty(manifest.id)) {
    throw new E2EEConfigurationError("Provider id must not be empty.");
  }
  if (!packagePattern.test(manifest.packageName)) {
    throw new E2EEConfigurationError(
      "Provider packageName must follow @absolutejs/e2ee-<provider>.",
    );
  }
  if (!nonEmpty(manifest.description) || !nonEmpty(manifest.version)) {
    throw new E2EEConfigurationError(
      "Provider description and version must not be empty.",
    );
  }
  if (manifest.roles.length === 0 || !unique(manifest.roles)) {
    throw new E2EEConfigurationError(
      "Provider roles must be non-empty and unique.",
    );
  }
  if (manifest.runtimes.length === 0 || !unique(manifest.runtimes)) {
    throw new E2EEConfigurationError(
      "Provider runtimes must be non-empty and unique.",
    );
  }
  if (manifest.protocols.length === 0 || !unique(manifest.protocols)) {
    throw new E2EEConfigurationError(
      "Provider protocols must be non-empty and unique.",
    );
  }
  if (
    manifest.security.supportedModes.length === 0 ||
    !unique(manifest.security.supportedModes)
  ) {
    throw new E2EEConfigurationError(
      "Supported security modes must be non-empty and unique.",
    );
  }
  if (
    manifest.security.assurance === "audited" &&
    (manifest.security.auditUrls === undefined ||
      manifest.security.auditUrls.length === 0)
  ) {
    throw new E2EEConfigurationError(
      "An audited provider must publish at least one audit URL.",
    );
  }
  if (
    manifest.security.supportedModes.includes("strict-e2ee") &&
    manifest.security.operatorCanDecrypt
  ) {
    throw new E2EEConfigurationError(
      "A provider whose operator can decrypt cannot claim strict-e2ee support.",
    );
  }

  return freezeManifest(manifest);
};

export const explainProviderCompatibility = (
  manifest: E2EEProviderManifest,
  requirements: E2EEProviderRequirements,
): ProviderCompatibility => {
  const reasons: string[] = [];

  if (
    requirements.pinnedProviderId !== undefined &&
    manifest.id !== requirements.pinnedProviderId
  ) {
    reasons.push(`provider id is not ${requirements.pinnedProviderId}`);
  }
  if (!manifest.runtimes.includes(requirements.runtime)) {
    reasons.push(`runtime ${requirements.runtime} is not supported`);
  }
  for (const role of requirements.roles) {
    if (!manifest.roles.includes(role)) reasons.push(`role ${role} is missing`);
  }
  for (const protocol of requirements.protocols ?? []) {
    if (!manifest.protocols.includes(protocol)) {
      reasons.push(`protocol ${protocol} is missing`);
    }
  }
  if (!manifest.security.supportedModes.includes(requirements.securityMode)) {
    reasons.push(`security mode ${requirements.securityMode} is not supported`);
  }
  if (
    requirements.minimumAssurance !== undefined &&
    assuranceRank[manifest.security.assurance] <
      assuranceRank[requirements.minimumAssurance]
  ) {
    reasons.push(
      `assurance ${manifest.security.assurance} is below ${requirements.minimumAssurance}`,
    );
  }
  if (
    requirements.operatorCanDecrypt !== undefined &&
    manifest.security.operatorCanDecrypt !== requirements.operatorCanDecrypt
  ) {
    reasons.push(
      requirements.operatorCanDecrypt
        ? "operator decryption is required but unavailable"
        : "operator can decrypt protected content",
    );
  }
  if (
    requirements.requireForwardSecrecy === true &&
    !manifest.security.forwardSecrecy
  ) {
    reasons.push("forward secrecy is required but unavailable");
  }
  if (
    requirements.requirePostCompromiseSecurity === true &&
    !manifest.security.postCompromiseSecurity
  ) {
    reasons.push("post-compromise security is required but unavailable");
  }
  if (
    requirements.privateKeyProtection !== undefined &&
    !requirements.privateKeyProtection.includes(
      manifest.security.privateKeyProtection,
    )
  ) {
    reasons.push(
      `private-key protection ${manifest.security.privateKeyProtection} is not allowed`,
    );
  }
  if (
    manifest.security.postQuantum &&
    requirements.allowPostQuantumClaim !== true
  ) {
    reasons.push("post-quantum claim was not explicitly allowed by policy");
  }

  return Object.freeze({
    compatible: reasons.length === 0,
    reasons: Object.freeze(reasons),
  });
};

export const selectE2EEProvider = <Provider extends E2EEProvider>(
  providers: readonly Provider[],
  requirements: E2EEProviderRequirements,
): Provider => {
  const rejected: Record<string, readonly string[]> = {};
  const compatible = providers.filter((provider) => {
    const result = explainProviderCompatibility(
      provider.manifest,
      requirements,
    );
    if (!result.compatible) rejected[provider.manifest.id] = result.reasons;
    return result.compatible;
  });

  if (compatible.length === 0) {
    throw new E2EEProviderSelectionError(
      "No E2EE provider satisfies the requested security policy.",
      Object.freeze(rejected),
    );
  }

  return compatible.toSorted((left, right) => {
    const assuranceDifference =
      assuranceRank[right.manifest.security.assurance] -
      assuranceRank[left.manifest.security.assurance];
    return assuranceDifference === 0
      ? left.manifest.id.localeCompare(right.manifest.id)
      : assuranceDifference;
  })[0]!;
};
