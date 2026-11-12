# Product Hunt launch kit

Prepared for a **2026-11-17** launch (00:00 America/Los_Angeles).

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

The Product Hunt MCP is **not authenticated** in this session. `get_my_account` returns:

> MCP server "https://mcp.producthunt.com/mcp" requires a login before it can register a client

Connect/authorize the Product Hunt account in the MCP client, then the launch can be drafted and
scheduled. No launch has been created or submitted.

## GitHub social preview

GitHub still has **no REST/GraphQL/`gh` endpoint** for the repository social preview as of 2026.
It is web-UI only:

1. Repository **Settings → Social preview → Edit**.
2. Upload `assets/social-card.png` (1280×630, under 1 MB).

`assets/social-card.png` is ready.

## Launch sequence (after MCP auth)

1. `get_launch_context` for `https://haqaliz.github.io/pry/` and `2026-11-17`; confirm the date
   is available and get topic/category/maker IDs.
2. `start_launch` with the listing fields from `copy.md`; this creates a private draft.
3. `prepare_launch_asset` for the thumbnail and four gallery images; attach the ready asset IDs.
4. `update_launch` with the video URL, launch date, makers, topics, categories, and first
   comment.
5. `get_launch` to review blockers and the preview.
6. `submit_launch` with `preview: true`; review the preview and side effects.
7. `submit_launch` with the returned `confirmation_token` only after explicit approval.
8. Add the Product Hunt badge to the site after the launch is live.

## Notes

- The listing is free and open source. Do not add a paid tier or a "secure" claim.
- Keep the ownership-gated, no-third-party-scanning positioning in the first comment.
- The video is silent and captioned in the cards; Product Hunt accepts MP4.
