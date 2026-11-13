# Product Hunt launch copy

**Launch date:** Tuesday, 2026-11-17 (00:00 America/Los_Angeles).
**Status:** scheduled (launch ID 1315776); public 2026-11-17 at 00:00 PT.

## Listing

- **Name:** Pry
- **Tagline:** Prove your app is exposed, not just suspicious.
- **Website:** https://haqaliz.github.io/pry/
- **GitHub:** https://github.com/haqaliz/pry
- **PyPI:** https://pypi.org/project/pry-scanner/
- **Pricing:** Free
- **Open source:** Yes (Apache-2.0)
- **Solo maker:** Yes
- **Topics:** Developer Tools, Security, Open Source, Technology
- **Categories:** Developer Tools, Security

**Description (short):**

> Pry proves an app you own is exposed by actually trying the exploit, then captures a signed,
> replayable proof. Ownership-gated, read-only by default. No pattern-matching verdicts, no
> "secure" claim.

## First maker comment

```html
<p>Hi Product Hunt. I built Pry because security scanners kept telling me things "look risky" without proving anything.</p>

<p>Pry is a CLI for apps you own. You declare the endpoint, the object pair, or the database path. It makes the real request, captures the exact response, and signs it. If it cannot reproduce the issue, it says <code>NOT_REPRODUCED</code>, never "safe".</p>

<p>What is in v0.1.1:</p>
<ul>
  <li>Ownership gate: DNS TXT or a well-known file before any live request.</li>
  <li>Local repos in a disposable Docker sandbox with no run-phase egress.</li>
  <li>Read-only floor: missing auth, secrets, served database files, CORS, errors, headers.</li>
  <li>Configured IDOR, local/live SSRF, rate-limit observations, provider database marker checks, and Level 2 writes.</li>
  <li>Ed25519 proof bundles, offline verification, read-only replay, and an HTML report.</li>
</ul>

<p>What it is not: no route discovery by guessing, no third-party scanning, no "secure" badge. It is open source and free.</p>

<p>I would love feedback on the finding format and on the checks you would want next. Try it with <code>uv tool install pry-scanner</code>, then <code>pry scan ./your-app --report</code>.</p>
```

## Gallery order and captions

| # | File | Caption |
|---|---|---|
| 1 | `gallery/01-hero.png` | Prove it. Don't guess it. A real local run with four EXPOSED findings. |
| 2 | `gallery/02-wedge.png` | The exploit is the verdict. Execute, capture, sign. |
| 3 | `gallery/03-proof.png` | Verify the proof offline. Ed25519, redacted, replayable. |
| 4 | `gallery/04-safety.png` | Ownership first. No "secure" claim. |

## Media

- **Thumbnail:** `thumbnail-240.png` (240×240).
- **Video:** `pry-product-hunt.mp4` (30.6s, 1280×720, silent). Intro card, real terminal demo,
  proof card, install/end card.
- **Gallery:** 1270×760 each.

## Links

- https://haqaliz.github.io/pry/
- https://github.com/haqaliz/pry
- https://pypi.org/project/pry-scanner/

## Launch-day checklist

- [ ] Connect the Product Hunt MCP / authorize the account.
- [ ] Create the private draft from https://haqaliz.github.io/pry/.
- [ ] Attach the 240×240 thumbnail, four gallery images, and the video.
- [ ] Check the Nov 17 availability in `get_launch_context`.
- [ ] Submit with `submit_launch` after a preview and explicit confirmation.
- [ ] Pin the first comment.
- [ ] Post the launch link on X/LinkedIn and relevant security communities.
- [ ] Reply to comments during the first 6 hours.
- [ ] Add the Product Hunt badge to the site after launch.
