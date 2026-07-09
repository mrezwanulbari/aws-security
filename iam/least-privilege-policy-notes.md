# Least-Privilege IAM Policy: Design Notes

Companion notes for [`least-privilege-policy-example.json`](least-privilege-policy-example.json), explaining the design decisions rather than just the policy syntax.

## Why Three Statements Instead of One Broad Allow

A single `s3:*` allow with a resource restriction is the common shortcut — it works, but it's not least-privilege, it's resource-scoped-privilege. The three-statement pattern here demonstrates the actual least-privilege discipline:

1. **Explicit action allowlist** (`GetObject`, `ListBucket` only) — the principal can do exactly what its job requires and nothing else, so a compromised credential's blast radius is bounded by function, not just by bucket.
2. **Explicit deny on unencrypted writes** — even though the allow statement doesn't grant `PutObject`, defense-in-depth means the deny statement stays in place so that if the allow scope is ever expanded later (a near-certainty over time), the encryption requirement doesn't silently disappear.
3. **VPC endpoint restriction** — ensures the access only works from within the expected network path, so a leaked credential used from outside the corporate network/VPC is denied regardless of whether the IAM permissions would otherwise allow it. This is the IAM-layer equivalent of network segmentation.

## Common Mistake This Avoids

Teams often write IAM policies once at project start and never revisit them as the project's actual access patterns evolve — the policy either becomes too permissive (broadened repeatedly to "just fix the error") or breaks legitimate new functionality (too rigid, causing developers to request broader access instead of a scoped addition). Tag-based conditions (`aws:PrincipalTag`) make the policy self-documenting about *who* it's meant for, which makes future review far faster than parsing ARNs alone.

---
*Part of the [aws-security](../README.md) repository.*
