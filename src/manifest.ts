import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "select an end-to-end encryption provider",
      "declare encrypted conversation security modes",
      "verify E2EE provider capabilities and assurance",
    ],
    keywords: [
      "e2ee",
      "encryption",
      "MLS",
      "secure messaging",
      "secure transfer",
      "provider",
    ],
    protocols: ["MLS", "HPKE"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "Provider-neutral E2EE contracts, explicit security modes, assurance manifests, deterministic provider selection, and conformance tools.",
    docsUrl: "https://github.com/absolutejs/e2ee",
    name: "@absolutejs/e2ee",
    tagline: "Choose and verify encrypted communication providers explicitly.",
  },
  settings: Type.Object({}, { additionalProperties: false }),
  wiring: [],
});
