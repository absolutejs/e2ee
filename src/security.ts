import { E2EEConfigurationError } from "./errors";
import type {
  AuthenticatedContext,
  ConversationState,
  DeviceCredential,
  E2EEKeyPackage,
  SecurityMode,
  SecurityModeTransition,
  SecretProcessingMode,
} from "./types";

export const DEFAULT_SECRET_PROCESSING_MODE: SecretProcessingMode =
  "tool-confined";

export const planSecurityModeTransition = (
  from: SecurityMode,
  to: SecurityMode,
): SecurityModeTransition => {
  if (from === to) {
    throw new E2EEConfigurationError(
      `Conversation is already using security mode ${from}.`,
    );
  }

  return Object.freeze({
    from,
    reinitializationRequired: true,
    requiresParticipantNotification: true,
    to,
  });
};

export const validateAuthenticatedContext = (
  context: AuthenticatedContext,
  now = Date.now(),
): void => {
  if (
    context.conversationId.trim().length === 0 ||
    context.purpose.trim().length === 0 ||
    context.senderId.trim().length === 0
  ) {
    throw new E2EEConfigurationError(
      "Authenticated context identifiers and purpose must not be empty.",
    );
  }
  if (
    !Number.isSafeInteger(context.securityEpoch) ||
    context.securityEpoch < 0
  ) {
    throw new E2EEConfigurationError(
      "Authenticated context securityEpoch must be a non-negative safe integer.",
    );
  }
  if (context.expiresAt !== undefined && context.expiresAt <= now) {
    throw new E2EEConfigurationError("Authenticated context has expired.");
  }
};

const requireIdentifier = (value: string, name: string): void => {
  if (value.trim().length === 0) {
    throw new E2EEConfigurationError(`${name} must not be empty.`);
  }
};

export const validateDeviceCredential = (
  credential: DeviceCredential,
  now = Date.now(),
): void => {
  requireIdentifier(credential.deviceId, "deviceId");
  requireIdentifier(credential.identityId, "identityId");
  if (credential.bytes.length === 0) {
    throw new E2EEConfigurationError("Device credential must not be empty.");
  }
  if (
    !Number.isSafeInteger(credential.issuedAt) ||
    credential.issuedAt < 0 ||
    credential.issuedAt > now
  ) {
    throw new E2EEConfigurationError("Device credential issuedAt is invalid.");
  }
  if (credential.expiresAt !== undefined && credential.expiresAt <= now) {
    throw new E2EEConfigurationError("Device credential has expired.");
  }
};

export const validateKeyPackage = (
  keyPackage: E2EEKeyPackage,
  now = Date.now(),
): void => {
  validateDeviceCredential(keyPackage.credential, now);
  requireIdentifier(keyPackage.id, "key package id");
  requireIdentifier(keyPackage.protocol, "key package protocol");
  if (keyPackage.bytes.length === 0) {
    throw new E2EEConfigurationError("Key package must not be empty.");
  }
  if (
    !Number.isSafeInteger(keyPackage.expiresAt) ||
    keyPackage.expiresAt <= now
  ) {
    throw new E2EEConfigurationError("Key package has expired.");
  }
};

export const validateConversationState = (state: ConversationState): void => {
  requireIdentifier(state.conversationId, "conversationId");
  if (state.bytes.length === 0) {
    throw new E2EEConfigurationError("Conversation state must not be empty.");
  }
  if (!Number.isSafeInteger(state.revision) || state.revision < 0) {
    throw new E2EEConfigurationError(
      "Conversation state revision must be a non-negative safe integer.",
    );
  }
};
