# Security Policy

## Supported versions

Only the latest `0.1.x` release is supported with security fixes.

## Reporting a vulnerability in Pry

**Do not open a public issue for a security vulnerability.**

Use GitHub private vulnerability reporting:

https://github.com/haqaliz/pry/security/advisories/new

Include:

- the Pry version (`pry --version`) and platform;
- the command and a minimal reproduction;
- the impact and any proof-of-concept;
- whether the issue affects Pry itself or a target it scanned.

Do not include real user data, live credentials, or third-party target details. Redact them.

You can expect an acknowledgment within 72 hours, a triage decision, and a coordinated
disclosure plan. Good-faith research on Pry itself is welcome; do not test against targets you
do not own or have written authorization to test.

## Scope

Pry is a scanning tool. This policy covers vulnerabilities in Pry's own code, packaging, and
default configuration — for example:

- an ownership-check bypass;
- a sandbox escape or unintended network access;
- credential, token, or proof-key leakage;
- a path that turns a read-only check into a write;
- a signed proof that can be forged or replayed as valid when it is not.

It does **not** cover vulnerabilities found in apps scanned with Pry. Report those to the app
owner through the process in [`ETHICS.md`](ETHICS.md).

## Scanning safely

Pry requires ownership proof before any live request, uses read-only checks by default, and
requires explicit confirmation for Level 1 and Level 2. If a check appears to touch shared
data, trigger a notification, or alter state, stop and report it as `UNVERIFIED`.

Never run Pry against a target you do not own or have written authorization to test.
