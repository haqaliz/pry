# Contributing to Pry

Thanks for your interest. Pry is a small, opinionated security tool: it proves an exposure by
reproducing it, and it never claims an app is "secure." Contributions that harden the
reproduction-and-proof path are the most valuable.

Read these first:

- [VISION.md](VISION.md) for the bet.
- [ETHICS.md](ETHICS.md) for the rules every check must follow.
- [docs/technical/ARCHITECTURE.md](docs/technical/ARCHITECTURE.md) for the own → intake → probe
  → prove → report pipeline.
- [docs/ROADMAP.md](docs/ROADMAP.md) for what is in and out of scope.

## Development setup

Pry is a Python 3.9+ package managed with [`uv`](https://github.com/astral-sh/uv). Docker is
required for local sandbox scans.

```bash
git clone https://github.com/haqaliz/pry.git
cd pry
uv sync
uv run pytest
```

The default suite is offline. Docker integration tests are opt-in:

```bash
PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
```

Build and check the package:

```bash
uv build
uvx twine check dist/*
```

## What we will merge

- A capability that reproduces a finding and captures a signed, replayable pair.
- A safety fix that reduces data touched, removes a write, or closes an ownership gap.
- A documentation fix that makes a claim more precise.
- A test that pins down a real edge case.

Every capability lands test-first: a failing test, then the smallest change that passes it.
Update `tests/test_docs_truth.py` when public docs change. No new dependency unless the standard
library and the existing stack cannot do the job; say why in the PR.

## What we will not merge

- Pattern-matching as a verdict. A heuristic may prioritize; only a reproduced pair may produce
  `EXPOSED`.
- A "SAFE" or "SECURE" verdict. The verdict space is `EXPOSED`, `NOT_REPRODUCED`, `UNVERIFIED`.
- A live check without ownership proof (`P1`) and the required confirmation.
- A read-only check that can write, notify, or exfiltrate more than the minimum.
- Discovery by guessing routes or object ownership.
- A hardening check dressed up as an exploit. Missing headers and rate limits are unsigned
  observations, never `EXPOSED`.

## Project layout

```text
src/pry/
  own/        P1: ownership verification and tokens
  intake/     P2: local Docker sandbox and snapshots
  probe/      P3/P4: floor, live, IDOR, SSRF, rate-limit, headers, database, writes
  proof/      P5: Ed25519 signed bundles and replay
  report/     P6: HTML report and JSONL corpus
  cli.py      pry scan | database | verify-ownership | verify-proof | replay | report | intake
tests/        offline by default; Docker tests opt-in; docs truth checks
docs/         architecture, capability roadmap, release and planning notes
```

Keep the module boundaries and naming style. A new probe needs a sidecar or in-process function,
a client path, a result shape, tests, and docs.

## Style

- Match the surrounding code: naming, comment density, and error causes.
- Keep comments for the *why* the code cannot show.
- Use stable machine-readable causes (`LOWER_SNAKE_CASE`) for every failure path.
- Redact credentials, cookies, API keys, database rows, and anything beyond the proof.
- Do not add a "secure" claim, a graded severity, or a false-positive-prone heuristic.

## Pull requests

Use the PR template. Keep a PR focused. Include:

- what changed and why;
- the failing test and the passing test;
- the commands you ran (`uv run pytest`, Docker tests, `uv build`);
- any safety or data-handling impact;
- docs updated (README, architecture, roadmap, docs truth).

Small, honest changes are easier to review than broad ones.

## Security

Do not open a public issue for a vulnerability in Pry itself. Use
[GitHub private vulnerability reporting](https://github.com/haqaliz/pry/security/advisories/new).
See [SECURITY.md](SECURITY.md).

## Code of conduct

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
