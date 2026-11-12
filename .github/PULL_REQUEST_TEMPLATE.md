<!-- Thanks for contributing to Pry. Keep PRs focused. See CONTRIBUTING.md. -->

## What and why

<!-- What does this change, and why? Link the issue if there is one (Closes #N). -->

## How it was tested

<!-- The tests you added or ran: `uv run pytest`, Docker tests, `uv build`. -->

## Safety and data handling

<!-- Does this touch ownership, credentials, writes, live targets, or proof data? -->

## Checklist

- [ ] Test-first: a failing test captured the behavior, then the code made it pass.
- [ ] `uv run pytest -q` is green (and Docker tests if relevant).
- [ ] `uv build` and `uvx twine check dist/*` pass for packaging changes.
- [ ] No new dependency without a reason.
- [ ] No `SAFE`/`SECURE` verdict and no pattern-matching as a verdict.
- [ ] Live checks still require ownership proof and confirmation.
- [ ] Credentials, cookies, API keys, and data beyond the proof are redacted.
- [ ] Docs updated (README, architecture, roadmap, `tests/test_docs_truth.py`) if the surface
      changed.
- [ ] No secrets or target data committed.
