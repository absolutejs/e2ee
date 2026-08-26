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

export type DeviceCredential = {
  readonly bytes: Uint8Array;
  readonly deviceId: string;
  readonly expiresAt?: number;
  readonly identityId: string;
  readonly issuedAt: number;
};

export type LocalDeviceCredential = DeviceCredential & {
  /** Opaque provider-owned reference. This is never private key material. */
  readonly keyHandle: string;
};

export type CredentialValidation = {
  readonly identityId: string;
  readonly status: "invalid" | "revoked" | "valid";
};

export type AuthenticationService = {
  issueDeviceCredential(input: {
    readonly deviceId: string;
    readonly identityId: string;
    readonly publicKey: Uint8Array;
  }): Promise<DeviceCredential>;
  sameIdentity(
    left: DeviceCredential,
    right: DeviceCredential,
  ): Promise<boolean>;
  validateDeviceCredential(input: {
    readonly credential: DeviceCredential;
    readonly publicKey: Uint8Array;
  }): Promise<CredentialValidation>;
};

export type E2EEKeyPackage = {
  readonly bytes: Uint8Array;
  readonly credential: DeviceCredential;
  readonly expiresAt: number;
  readonly id: string;
  readonly protocol: string;
};

export type KeyPackageDirectory = {
  claim(identityId: string): Promise<E2EEKeyPackage | undefined>;
  publish(keyPackage: E2EEKeyPackage): Promise<void>;
  remove(input: {
    readonly deviceId: string;
    readonly id: string;
  }): Promise<void>;
};

export type DeliveryMessageKind =
  "application" | "commit" | "proposal" | "welcome";

export type DeliveryMessage = {
  readonly bytes: Uint8Array;
  readonly conversationId: string;
  readonly id: string;
  readonly kind: DeliveryMessageKind;
  readonly recipientDeviceId?: string;
};

export type DeliveryCursor = {
  readonly deviceId: string;
  readonly value?: string;
};

export type DeliveryBatch = {
  readonly cursor?: string;
  readonly messages: readonly DeliveryMessage[];
};

export type DeliveryService = {
  acknowledge(input: {
    readonly cursor: string;
    readonly deviceId: string;
  }): Promise<void>;
  receive(cursor: DeliveryCursor): Promise<DeliveryBatch>;
  send(messages: readonly DeliveryMessage[]): Promise<void>;
};

export type ConversationState = {
  readonly bytes: Uint8Array;
  readonly conversationId: string;
  readonly revision: number;
};

export type ConversationStateStore = {
  load(conversationId: string): Promise<ConversationState | undefined>;
  remove(conversationId: string, expectedRevision: number): Promise<boolean>;
  save(input: {
    readonly expectedRevision?: number;
    readonly state: ConversationState;
  }): Promise<boolean>;
};

export type RecoveryRequest = {
  readonly conversationId: string;
  readonly expiresAt: number;
  readonly id: string;
  readonly issuedAt: number;
  readonly lostDeviceIds: readonly string[];
  readonly replacementCredential: DeviceCredential;
  readonly securityMode: "managed-recovery";
  readonly subjectIdentityId: string;
};

export type RecoveryGrant = {
  readonly authorityId: string;
  /** Opaque signed or MAC-authenticated proof over the complete request. */
  readonly bytes: Uint8Array;
  readonly expiresAt: number;
  readonly issuedAt: number;
  readonly requestId: string;
};

export type RecoveryGrantVerifier = {
  readonly authorityId: string;
  verify(input: {
    readonly grant: RecoveryGrant;
    readonly request: RecoveryRequest;
  }): Promise<boolean>;
};

export type RecoveryAuthority = RecoveryGrantVerifier & {
  /** Issuance is expected to enforce the authority's approval ceremony. */
  issue(request: RecoveryRequest): Promise<RecoveryGrant>;
};

export type ConversationMember = {
  readonly credential: DeviceCredential;
  readonly index: number;
};

export type MembershipChange = {
  readonly epoch: number;
  readonly handshake: readonly ProtectedMessage[];
  readonly welcomes: readonly {
    readonly deviceId: string;
    readonly bytes: Uint8Array;
  }[];
};

export type MessagingProcessResult =
  | {
      readonly kind: "application";
      readonly message: DecryptedMessage;
    }
  | {
      readonly epoch: number;
      readonly kind: "membership-change" | "state-change";
    };

export type MessagingSession = {
  readonly conversationId: string;
  readonly epoch: number;
  /** Mode authenticated by the provider's conversation state. */
  readonly securityMode: SecurityMode;
  addMembers(keyPackages: readonly E2EEKeyPackage[]): Promise<MembershipChange>;
  close(): Promise<void>;
  members(): Promise<readonly ConversationMember[]>;
  protect(
    plaintext: Uint8Array,
    authenticatedContext: AuthenticatedContext,
  ): Promise<ProtectedMessage>;
  process(
    message: ProtectedMessage,
  ): Promise<MessagingProcessResult | undefined>;
  removeMembers(deviceIds: readonly string[]): Promise<MembershipChange>;
  replaceMembers(input: {
    readonly add: readonly E2EEKeyPackage[];
    readonly removeDeviceIds: readonly string[];
  }): Promise<MembershipChange>;
  selfUpdate(): Promise<MembershipChange>;
};

export type MessagingProvider = E2EEProvider & {
  createDeviceCredential(input: {
    readonly deviceId: string;
    readonly identityId: string;
  }): Promise<LocalDeviceCredential>;
  createKeyPackage(input: {
    readonly credential: LocalDeviceCredential;
    readonly expiresAt: number;
  }): Promise<E2EEKeyPackage>;
  createConversation(input: {
    readonly conversationId: string;
    readonly creatorCredential: LocalDeviceCredential;
    readonly securityMode: SecurityMode;
  }): Promise<MessagingSession>;
  joinConversation(input: {
    readonly credential: LocalDeviceCredential;
    readonly expectedSecurityMode: SecurityMode;
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
