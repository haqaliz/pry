# Hacker News submission

Hacker News has no scheduling API. Submit manually when you can stay in the thread.

## Prefilled submit link

Open this and review the fields:

https://news.ycombinator.com/submitlink?u=https%3A%2F%2Fgithub.com%2Fhaqaliz%2Fpry&t=Show%20HN%3A%20Pry%20%E2%80%93%20Prove%20your%20app%20is%20exposed%2C%20not%20just%20suspicious

If the prefill does not stick, use:

- **Title:** `Show HN: Pry – Prove your app is exposed, not just suspicious`
- **URL:** `https://github.com/haqaliz/pry`
- **Submit page:** https://news.ycombinator.com/submit

## First comment

Post this as the author comment right after submitting:

```text
Author here. I built Pry because most scanners tell you an endpoint "looks risky" without proving it. Pry makes the request that should have been blocked, captures the response, and signs the pair. If it cannot reproduce, it says NOT_REPRODUCED, never "safe".

It is a CLI. Local repos run in a disposable Docker sandbox; live URLs need a DNS TXT or well-known-file ownership token. Read-only is the default; Level 1 and Level 2 need explicit confirmation. No route discovery by guessing, no third-party scanning, no upload by default.

What is in 0.1.1: missing auth, secrets, served database files, CORS/errors/headers, configured IDOR, local/live SSRF, rate-limit observations, provider database marker checks, Level 2 writes, Ed25519 proof bundles, offline verification, live read-only replay, and an HTML report.

Install: uv tool install pry-scanner
Repo: https://github.com/haqaliz/pry
Site: https://haqaliz.github.io/pry/

I would especially value feedback on the proof format and on which checks are missing. Happy to answer questions.
```

## Timing

Do not submit the same day as Product Hunt if you want to engage with both threads. Product Hunt is
scheduled for **2026-11-17**; Hacker News is a better fit on **2026-11-18 or 2026-11-19**, US
morning (ET). HN does not guarantee ranking, and asking for upvotes is against the rules.

## Checklist

- [ ] Open the prefilled link and confirm title and URL.
- [ ] Submit.
- [ ] Immediately post the first comment above.
- [ ] Stay in the thread for the first few hours.
- [ ] Answer ownership, data-handling, and false-positive questions plainly.
- [ ] Do not ask for upvotes or coordinate voting.
