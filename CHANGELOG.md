# Changelog

## 0.8.0

- Replace opaque MLS-state escrow with request-bound recovery grants. Recovery
  authorities issue and verify authorization proofs but never receive live group
  state through the core contract.
- Add an atomic member-replacement primitive for RFC 9750-style state-loss
  recovery: add the replacement device and remove lost leaves in one MLS epoch.

## 0.7.0

- Require messaging sessions to expose their authenticated security mode.
- Require callers joining a Welcome to provide the expected security mode so
  providers can reject strict/managed mode substitution.

## 0.6.0

- Add fail-closed independent-audit evidence bound to exact package versions,
  report digests, auditor identities, finding severity, and validity windows.
- Let deployment policy restrict acceptance to an explicit auditor allowlist.

## 0.4.0

- Bind Authentication Service validation to the MLS signature public key.
- Require initial members to be added through `addMembers()` so every caller
  receives and delivers the resulting Welcome messages.

## 0.3.0

- Require security-mode transitions to create a new conversation instead of
  allowing a provider to relabel existing MLS group state in place.

## 0.2.0

- Add MLS device credential and KeyPackage contracts.
- Add authentication, key-package directory, delivery, and durable
  conversation-state boundaries.
- Add explicit managed-recovery authority and membership lifecycle contracts.
- Add MLS messaging-provider conformance checks.

## 0.1.0

- Establish provider-neutral E2EE manifests, security modes, selection, and
  conformance contracts.

# 0.5.0

- Add versioned, immutable provider certification reports and fail-closed policy
  evaluation for exact releases, runtimes, freshness, scenarios, vectors, and
  independent implementation claims.
