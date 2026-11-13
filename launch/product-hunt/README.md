# Product Hunt launch kit

Scheduled for a **2026-11-17** launch (00:00 America/Los_Angeles).

## Assets

| Asset | Path | Size |
|---|---|---|
| Thumbnail | `thumbnail-240.png` | 240×240 |
| Gallery 1 | `gallery/01-hero.png` | 1270×760 |
| Gallery 2 | `gallery/02-wedge.png` | 1270×760 |
| Gallery 3 | `gallery/03-proof.png` | 1270×760 |
| Gallery 4 | `gallery/04-safety.png` | 1270×760 |
| Video | `pry-product-hunt.mp4` | 30.6s, 1280×720, silent |
| Copy | `copy.md` | listing, first comment, captions |

The SVG sources and `make_assets.py` are included so the cards can be regenerated. The video
uses `assets/pry-demo.mp4` plus `end-card.png`; rebuild it with ffmpeg if the demo changes.

## Product Hunt MCP

Authenticated and used to create and schedule the launch. The draft was submitted with the
Nov 17 date; status is `scheduled`, assessment `no_known_blockers`.

The video is **intentionally not attached**: Product Hunt only accepts YouTube or Loom links
for the video field, and the prepared file is a local/GitHub MP4. The launch does not need it.

## GitHub social preview

Uploaded and confirmed on the repository. GitHub has no REST/GraphQL/`gh` endpoint for this as
of 2026, so it was a one-time web-UI upload of `assets/social-card.png`.

## Launch status

1. Done: date checked, draft created, assets attached, first comment and categories set.
2. Done: preview reviewed and submitted; status is `scheduled` for 2026-11-17.
3. Optional: add a YouTube/Loom video URL with `update_launch`.
4. Add the Product Hunt badge to the site after the launch is live.
5. Hacker News submission is prepared at `launch/hacker-news/submission.md`; submit manually
   on Nov 18 or 19 so it does not collide with the Product Hunt launch.

## Notes

- The listing is free and open source. Do not add a paid tier or a "secure" claim.
- Keep the ownership-gated, no-third-party-scanning positioning in the first comment.
- The video is silent and captioned in the cards; Product Hunt accepts MP4.
