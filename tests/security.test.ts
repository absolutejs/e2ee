import { describe, expect, test } from "bun:test";
import {
  DEFAULT_SECRET_PROCESSING_MODE,
  E2EEConfigurationError,
  planSecurityModeTransition,
  validateAuthenticatedContext,
} from "../src";

describe("security modes", () => {
  test("defaults secret handling to tool confinement", () => {
    expect(DEFAULT_SECRET_PROCESSING_MODE).toBe("tool-confined");
  });

  test("requires reinitialization and participant notification", () => {
    expect(
      planSecurityModeTransition("strict-e2ee", "managed-recovery"),
    ).toEqual({
      from: "strict-e2ee",
      reinitializationRequired: true,
      requiresParticipantNotification: true,
      to: "managed-recovery",
    });
  });

  test("rejects a no-op mode transition", () => {
    expect(() =>
      planSecurityModeTransition("strict-e2ee", "strict-e2ee"),
    ).toThrow(E2EEConfigurationError);
  });
});

describe("authenticated context", () => {
  test("accepts a purpose-bound future context", () => {
    expect(() =>
      validateAuthenticatedContext(
        {
          conversationId: "conversation-1",
          expiresAt: 2_000,
          purpose: "verification.submit",
          securityEpoch: 3,
          senderId: "user-1",
        },
        1_000,
      ),
    ).not.toThrow();
  });

  test("rejects expired and invalid contexts", () => {
    expect(() =>
      validateAuthenticatedContext(
        {
          conversationId: "conversation-1",
          expiresAt: 999,
          purpose: "verification.submit",
          securityEpoch: 3,
          senderId: "user-1",
        },
        1_000,
      ),
    ).toThrow("expired");

    expect(() =>
      validateAuthenticatedContext({
        conversationId: "",
        purpose: "verification.submit",
        securityEpoch: -1,
        senderId: "user-1",
      }),
    ).toThrow(E2EEConfigurationError);
  });
});
