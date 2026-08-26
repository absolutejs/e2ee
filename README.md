# `@absolutejs/e2ee`

Provider-neutral E2EE contracts, explicit security modes, assurance manifests,
provider selection, and conformance tools for AbsoluteJS.

This package is the stable seam between applications and implementations in the
[`e2ee-providers`](https://github.com/absolutejs/e2ee-providers) repository. It
does **not** invent cryptography, silently select a provider, or claim that unlike
providers have equivalent security.

> This is an early `0.x` release. The core package does not itself encrypt data,
> and no provider is production-approved until its published assurance and audit
> gates pass.

## Install

```bash
bun add @absolutejs/e2ee
```

## Select a provider explicitly

```ts
import { selectE2EEProvider } from "@absolutejs/e2ee";

const selected = selectE2EEProvider(providers, {
  minimumAssurance: "reviewed",
  operatorCanDecrypt: false,
  protocols: ["MLS-1.0"],
  roles: ["messaging"],
  runtime: "browser",
  securityMode: "strict-e2ee",
});

console.log(selected.manifest.packageName);
```

Selection fails closed and explains why each provider was rejected. Applications
may pin a provider ID when they need deterministic deployment rather than accepting
the highest compatible assurance level.

## Explicit modes

- `strict-e2ee`: only verified participant devices can decrypt conversation
  history. Losing all verified devices and exports may permanently lose history.
- `managed-recovery`: clients create recovery material for a visibly identified
  recovery authority. It is never enabled silently.

Sensitive agent exchange additionally declares whether a value is
`tool-confined`, `endpoint-visible`, or `model-visible`. `tool-confined` is the
recommended default.

## Scope

The `0.2.x` line adds the application boundaries required around an MLS engine:
device credentials, KeyPackages, membership changes, delivery, durable
compare-and-set state, and an explicit recovery authority. These are contracts,
not hosted services. Implementations remain in provider packages.

MLS deliberately does not define an application's Authentication Service or
Delivery Service. AbsoluteJS keeps those dependencies visible so a cryptographic
engine cannot silently become the identity authority, transport, or recovery
authority. Strict E2EE never receives a `RecoveryAuthority`; managed recovery
must identify and configure one explicitly.

Changing modes is not a session mutation. Call
`planSecurityModeTransition()`, create a new conversation in the requested
mode, re-add verified devices, and visibly retire the prior conversation.
New conversations begin with their creator only; add every other device through
`addMembers()` so its Welcome message cannot be accidentally discarded.
Joining a Welcome requires `expectedSecurityMode`, and the returned session
exposes the mode authenticated by provider state. Callers must reject any
strict/managed mismatch instead of trusting delivery metadata.

Public TypeScript contracts use type aliases rather than interfaces so unions,
intersections, and provider capability composition stay explicit.

See [SECURITY.md](./SECURITY.md) before relying on this package for protected data.

## Version-bound certification

Provider capability claims and provider certification are separate. A certification
report binds the provider ID, package name, exact package version, runtime, suite,
scenarios, implementation identities, vector sources, and an evidence digest.
`checkE2EECertification()` rejects stale reports, reports for another release or
runtime, and missing policy claims.

An `independent-audit` claim additionally requires an HTTPS report and SHA-256
digest, an exact package/version scope, an auditor identity, a future validity
date, and zero unresolved critical or high findings. Deployments can set
`trustedAuditorIds`; the library does not pretend that a provider's
self-declaration proves reviewer independence. Any provider release or scoped
engine change requires new audit evidence.

The claims deliberately distinguish shared conformance, known-answer vectors, and
cross-implementation testing. Passing the MLS Working Group vectors does not by
itself prove application interoperability: RFC 9750 leaves Authentication Service,
Delivery Service, identity, and application framing choices to deployments.

## License

Apache-2.0
