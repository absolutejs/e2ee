import { describe, expect, test } from "bun:test";
import {
  DEFAULT_SECRET_PROCESSING_MODE,
  E2EEConfigurationError,
  planSecurityModeTransition,
  requireMessagingSessionMode,
  validateAuthenticatedContext,
  validateConversationState,
  validateDeviceCredential,
  validateKeyPackage,
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

  test("rejects a session whose authenticated mode differs", () => {
    expect(() =>
      requireMessagingSessionMode(
        { securityMode: "managed-recovery" },
        "strict-e2ee",
      ),
    ).toThrow("does not match");
  });
});

describe("MLS lifecycle inputs", () => {
  const credential = {
    bytes: new Uint8Array([1]),
    deviceId: "device-1",
    identityId: "user-1",
    issuedAt: 1_000,
  };

  test("accepts bounded device, key-package, and state records", () => {
    expect(() => validateDeviceCredential(credential, 2_000)).not.toThrow();
    expect(() =>
      validateKeyPackage(
        {
          bytes: new Uint8Array([2]),
          credential,
          expiresAt: 3_000,
          id: "key-package-1",
          protocol: "MLS-1.0",
        },
        2_000,
      ),
    ).not.toThrow();
    expect(() =>
      validateConversationState({
        bytes: new Uint8Array([3]),
        conversationId: "conversation-1",
        revision: 0,
      }),
    ).not.toThrow();
  });

  test("rejects expired or structurally empty records", () => {
    expect(() =>
      validateDeviceCredential({ ...credential, deviceId: "" }, 2_000),
    ).toThrow("deviceId");
    expect(() =>
      validateKeyPackage(
        {
          bytes: new Uint8Array([2]),
          credential,
          expiresAt: 2_000,
          id: "key-package-1",
          protocol: "MLS-1.0",
        },
        2_000,
      ),
    ).toThrow("expired");
    expect(() =>
      validateConversationState({
        bytes: new Uint8Array(),
        conversationId: "conversation-1",
        revision: 0,
      }),
    ).toThrow("must not be empty");
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
