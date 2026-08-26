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

The first `0.x` line establishes provider capability and assurance contracts,
security policy, deterministic provider selection, and a shared conformance API.
MLS engines, native key stores, recovery authorities, transports, conversations,
and agent exchange are implemented in separate packages and releases.

Public TypeScript contracts use type aliases rather than interfaces so unions,
intersections, and provider capability composition stay explicit.

See [SECURITY.md](./SECURITY.md) before relying on this package for protected data.

## License

Apache-2.0
