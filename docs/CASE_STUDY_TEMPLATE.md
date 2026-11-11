# Case Study Template (M1.4)

Use this only after the app owner has approved publication and `ETHICS.md` has been followed.
Redact all user data, credentials, and third-party details.

## Title

`<What was reproduced> in <app type>`

## Summary

- **Target:** `<owned app / staging URL>` (do not publish a customer name without permission)
- **Authorization:** `<ownership proof used; date>`
- **Intensity:** `<0 / 1 / 2>`
- **Date:** `<YYYY-MM-DD>`
- **Verdict:** `EXPOSED` / `NOT_REPRODUCED` / `UNVERIFIED`

## What was run

```bash
pry scan <target> <flags>
```

## What was reproduced

- **Probe:** `<missing auth / IDOR / secrets / database / SSRF / write / ...>`
- **Request:** `<method and path; redact credentials>`
- **Response:** `<status and the minimum body excerpt>`
- **Why this is unauthorized:** `<one paragraph>`

## Proof

- **Bundle:** `<bundle_id>`
- **Fingerprint:** `sha256:<...>`
- **Replay:** `MATCH` / `MISMATCH` / not replayed
- **What the proof does not show:** `<no global auth claim / one object pair / one path / etc.>`

## Impact

`<What data or action was reachable; do not overclaim.>`

## Remediation

`<What the owner changed; date verified>`

## Disclosure timeline

| Date | Event |
|---|---|
| `<date>` | Finding reproduced |
| `<date>` | Owner notified |
| `<date>` | Fix deployed |
| `<date>` | Published with approval |

## Lessons

`<What this says about the product or the check.>`

## Limits

- This is one reproduced pair, not a security audit.
- A clean scan would have been `NOT_REPRODUCED`, never "secure."
