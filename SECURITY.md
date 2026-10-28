# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

If Anti-REA itself has a security problem — e.g. a harden transform corrupts binaries, the MCP server misbehaves, or a guard gives false assurance — please open a [GitHub Security Advisory](../../security/advisories/new) (private) rather than a public issue.

Please include: affected command, artifact type, reproduction steps, and expected vs. actual behavior.

## Scope notes

- Anti-REA is an **offline developer tool**. It performs no telemetry and makes no network calls.
- A "harden transform that changes runtime semantics" is a critical bug by definition — our test suite exists to prevent exactly that.
- Guard libraries score *possible* analysis environments and are deliberately conservative. A documented false-positive pattern (e.g. legitimate Job Object usage) is a bug worth reporting; an attacker defeating a guard by forking the attacking tool is a known limitation, not a vulnerability (see README threat model).
