import { E2EEConfigurationError } from "./errors";
import type {
  AuthenticatedContext,
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
