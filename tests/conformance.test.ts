import { expect, test } from "bun:test";
import {
  checkE2EEProviderConformance,
  checkMessagingProviderConformance,
} from "../src/conformance";
import { defineE2EEProviderManifest, type MessagingProvider } from "../src";

test("provider conformance is test-runner neutral and structured", async () => {
  const manifest = defineE2EEProviderManifest({
    contract: 1,
    costModel: "free",
    description: "Conformance fixture",
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
      privateKeyProtection: "exportable",
      supportedModes: ["strict-e2ee"],
    },
    version: "0.1.0",
  });

  const result = await checkE2EEProviderConformance({
    createProvider: () => ({ manifest }),
    validRequirement: {
      minimumAssurance: "experimental",
      operatorCanDecrypt: false,
      protocols: ["MLS-1.0"],
      roles: ["messaging"],
      runtime: "bun",
      securityMode: "strict-e2ee",
    },
  });

  expect(result).toEqual({ issues: [], manifest, passed: true });
  expect(Object.isFrozen(result)).toBe(true);
  expect(Object.isFrozen(result.issues)).toBe(true);
});

test("messaging conformance requires the MLS security properties", async () => {
  const manifest = defineE2EEProviderManifest({
    contract: 1,
    costModel: "free",
    description: "Messaging conformance fixture",
    id: "messaging-fixture",
    packageName: "@absolutejs/e2ee-messaging-fixture",
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
    version: "0.0.1",
  });
  const unavailable = async (): Promise<never> => {
    throw new Error("not exercised by manifest conformance");
  };
  const provider: MessagingProvider = {
    createConversation: unavailable,
    createDeviceCredential: unavailable,
    createKeyPackage: unavailable,
    joinConversation: unavailable,
    manifest,
    restoreConversation: unavailable,
    sealConversationState: unavailable,
  };

  expect(
    await checkMessagingProviderConformance({ createProvider: () => provider }),
  ).toMatchObject({ issues: [], passed: true });
});
