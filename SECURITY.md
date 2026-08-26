# Security policy

`@absolutejs/e2ee` is an early `0.x` provider contract. It does not itself
implement encryption and must not be treated as a completed or audited secure
messaging system.

Do not report security vulnerabilities through a public issue. Email
security@absolutejs.com with a description, affected versions, reproduction, and
impact. Do not include real credentials, private keys, or user content.

Only the latest published `0.x` minor is supported during initial development.
That policy will be expanded before a stable security claim is made.

Audit metadata is admission evidence, not a cryptographic proof of auditor
independence. Production deployments must maintain a reviewed auditor allowlist,
verify the published report digest, and reject expired or out-of-scope reports.
