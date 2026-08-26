import { E2EEConfigurationError } from "./errors";
import type {
  AuthenticatedContext,
  ConversationState,
  DeviceCredential,
  E2EEKeyPackage,
  MessagingSession,
  RecoveryGrant,
  RecoveryRequest,
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

export const requireMessagingSessionMode = (
  session: Pick<MessagingSession, "securityMode">,
  expected: SecurityMode,
): void => {
  if (session.securityMode !== expected)
    throw new E2EEConfigurationError(
      `Messaging session mode ${session.securityMode} does not match required mode ${expected}.`,
    );
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

export const validateRecoveryRequest = (
  request: RecoveryRequest,
  maximumTtlMs: number,
  now = Date.now(),
): void => {
  requireIdentifier(request.id, "recovery request id");
  requireIdentifier(request.conversationId, "conversationId");
  requireIdentifier(request.subjectIdentityId, "subjectIdentityId");
  validateDeviceCredential(request.replacementCredential, now);
  if (
    request.securityMode !== "managed-recovery" ||
    request.replacementCredential.identityId !== request.subjectIdentityId
  )
    throw new E2EEConfigurationError(
      "Recovery request mode or replacement identity is invalid.",
    );
  const lost = new Set(request.lostDeviceIds);
  if (
    lost.size === 0 ||
    lost.size !== request.lostDeviceIds.length ||
    request.lostDeviceIds.some((deviceId) => deviceId.trim().length === 0) ||
    lost.has(request.replacementCredential.deviceId)
  )
    throw new E2EEConfigurationError(
      "Recovery request lost devices must be unique, non-empty, and distinct from the replacement device.",
    );
  if (
    !Number.isSafeInteger(maximumTtlMs) ||
    maximumTtlMs < 1 ||
    !Number.isSafeInteger(request.issuedAt) ||
    !Number.isSafeInteger(request.expiresAt) ||
    request.issuedAt > now ||
    request.expiresAt <= now ||
    request.expiresAt - request.issuedAt > maximumTtlMs
  )
    throw new E2EEConfigurationError(
      "Recovery request timestamps violate policy.",
    );
};

export const validateRecoveryGrant = (
  grant: RecoveryGrant,
  request: RecoveryRequest,
  now = Date.now(),
): void => {
  requireIdentifier(grant.authorityId, "recovery authority id");
  requireIdentifier(grant.requestId, "recovery grant request id");
  if (grant.bytes.length === 0)
    throw new E2EEConfigurationError("Recovery grant proof must not be empty.");
  if (
    grant.requestId !== request.id ||
    !Number.isSafeInteger(grant.issuedAt) ||
    !Number.isSafeInteger(grant.expiresAt) ||
    grant.issuedAt < request.issuedAt ||
    grant.issuedAt > now ||
    grant.expiresAt <= now ||
    grant.expiresAt > request.expiresAt
  )
    throw new E2EEConfigurationError(
      "Recovery grant is expired or not bound to the request.",
    );
};
