export const E2EE_PROVIDER_CONTRACT = 1 as const;

export type SecurityMode = "managed-recovery" | "strict-e2ee";

export type SecretProcessingMode =
  "endpoint-visible" | "model-visible" | "tool-confined";

export type E2EEProviderRole =
  "envelope" | "key-custody" | "messaging" | "recovery" | "transport";

export type E2EERuntime =
  "browser" | "bun" | "capacitor-android" | "capacitor-ios" | "node";

export type AssuranceLevel = "audited" | "experimental" | "reviewed";

export type CostModel = "byo" | "free" | "paid-paas";

export type PrivateKeyProtection =
  "exportable" | "non-exportable" | "provider-managed";

export type E2EEProviderSecurity = {
  readonly assurance: AssuranceLevel;
  readonly auditUrls?: readonly string[];
  readonly forwardSecrecy: boolean;
  readonly operatorCanDecrypt: boolean;
  readonly postCompromiseSecurity: boolean;
  readonly postQuantum: boolean;
  readonly privateKeyProtection: PrivateKeyProtection;
  readonly supportedModes: readonly SecurityMode[];
};

export type E2EEProviderManifest = {
  readonly contract: typeof E2EE_PROVIDER_CONTRACT;
  readonly costModel: CostModel;
  readonly description: string;
  readonly id: string;
  readonly packageName: `@absolutejs/e2ee-${string}`;
  readonly protocols: readonly string[];
  readonly roles: readonly E2EEProviderRole[];
  readonly runtimes: readonly E2EERuntime[];
  readonly security: E2EEProviderSecurity;
  readonly version: string;
};

export type E2EEProviderRequirements = {
  readonly allowPostQuantumClaim?: boolean;
  readonly minimumAssurance?: AssuranceLevel;
  readonly operatorCanDecrypt?: boolean;
  readonly pinnedProviderId?: string;
  readonly privateKeyProtection?: readonly PrivateKeyProtection[];
  readonly protocols?: readonly string[];
  readonly requireForwardSecrecy?: boolean;
  readonly requirePostCompromiseSecurity?: boolean;
  readonly roles: readonly E2EEProviderRole[];
  readonly runtime: E2EERuntime;
  readonly securityMode: SecurityMode;
};

export type E2EEProvider = {
  readonly manifest: E2EEProviderManifest;
};

export type ProviderCompatibility = {
  readonly compatible: boolean;
  readonly reasons: readonly string[];
};

export type SecurityModeTransition = {
  readonly from: SecurityMode;
  readonly reinitializationRequired: true;
  readonly requiresParticipantNotification: true;
  readonly to: SecurityMode;
};

export type AuthenticatedContext = {
  readonly conversationId: string;
  readonly expiresAt?: number;
  readonly purpose: string;
  readonly securityEpoch: number;
  readonly senderId: string;
};

export type ProtectedMessage = {
  readonly authenticatedContext: AuthenticatedContext;
  readonly bytes: Uint8Array;
  readonly protocol: string;
};

export type DecryptedMessage = {
  readonly authenticatedContext: AuthenticatedContext;
  readonly plaintext: Uint8Array;
  readonly senderCredential: Uint8Array;
};

export type MessagingSession = {
  readonly conversationId: string;
  readonly epoch: number;
  addMembers(credentials: readonly Uint8Array[]): Promise<ProtectedMessage>;
  close(): Promise<void>;
  protect(
    plaintext: Uint8Array,
    authenticatedContext: AuthenticatedContext,
  ): Promise<ProtectedMessage>;
  process(message: ProtectedMessage): Promise<DecryptedMessage | undefined>;
  reinitialize(securityMode: SecurityMode): Promise<ProtectedMessage>;
  removeMembers(credentialIds: readonly string[]): Promise<ProtectedMessage>;
};

export type MessagingProvider = E2EEProvider & {
  createConversation(input: {
    readonly conversationId: string;
    readonly creatorCredential: Uint8Array;
    readonly initialMemberCredentials?: readonly Uint8Array[];
    readonly securityMode: SecurityMode;
  }): Promise<MessagingSession>;
  joinConversation(input: {
    readonly credential: Uint8Array;
    readonly welcome: Uint8Array;
  }): Promise<MessagingSession>;
  restoreConversation(input: {
    readonly sealedState: Uint8Array;
  }): Promise<MessagingSession>;
  sealConversationState(session: MessagingSession): Promise<Uint8Array>;
};

export type EnvelopeProvider = E2EEProvider & {
  open(input: {
    readonly envelope: Uint8Array;
    readonly expectedContext: AuthenticatedContext;
    readonly recipientKeyHandle: string;
  }): Promise<Uint8Array>;
  seal(input: {
    readonly authenticatedContext: AuthenticatedContext;
    readonly plaintext: Uint8Array;
    readonly recipientPublicKey: Uint8Array;
  }): Promise<Uint8Array>;
};
