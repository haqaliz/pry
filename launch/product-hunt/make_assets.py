#!/usr/bin/env python3
"""Generate the Product Hunt gallery SVGs and PNGs for Pry.

Run from the repo root: python3 launch/product-hunt/make_assets.py
Requires rsvg-convert on PATH.
"""

import subprocess
from pathlib import Path
from xml.sax.saxutils import escape
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MARK_INNER = re.search(
    r"<svg[^>]*>(.*)</svg>",
    (ROOT / "assets" / "pry-mark.svg").read_text(encoding="utf-8"),
    re.S,
).group(1)
GALLERY = HERE / "gallery"
GALLERY.mkdir(parents=True, exist_ok=True)

W, H = 1270, 760
INK = "#0b1116"
PANEL = "#101820"
LINE = "#22303a"
TEXT = "#eef3f6"
MUTED = "#9fb0bc"
ACCENT = "#fe0100"
SOFT = "#ff4d4f"


def esc(value):
    return escape(value)


def text(x, y, value, size=22, fill=TEXT, weight=400, family="Helvetica, Arial, sans-serif", extra=""):
    return (
        '<text x="%d" y="%d" font-family="%s" font-size="%d" font-weight="%d" '
        'fill="%s"%s>%s</text>'
        % (x, y, family, size, weight, fill, extra, esc(value))
    )


def mono(x, y, value, size=17, fill=TEXT):
    return text(x, y, value, size=size, fill=fill, family="Menlo, Consolas, monospace")


def frame(eyebrow, title, body, footer):
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">' % (W, H, W, H),
        '<rect width="%d" height="%d" fill="%s"/>' % (W, H, INK),
        '<rect x="0" y="0" width="8" height="%d" fill="%s"/>' % (H, ACCENT),
        '<svg x="72" y="64" width="78" height="72" viewBox="250 260 520 480">%s</svg>' % MARK_INNER,
        text(172, 98, "PRY", 28, TEXT, 700),
        text(172, 126, eyebrow, 15, SOFT, 600),
        text(72, 236, title[0], 64, TEXT, 700, extra=' letter-spacing="-2"'),
        text(72, 306, title[1], 64, TEXT, 700, extra=' letter-spacing="-2"'),
    ]
    y = 360
    for line in body:
        parts.append(text(72, y, line, 23, MUTED))
        y += 34
    parts.append(text(72, 704, footer, 16, "#66757f", family="Menlo, Consolas, monospace"))
    return parts


def terminal(x, y, w, h, lines):
    parts = [
        '<g>',
        '<rect x="%d" y="%d" width="%d" height="%d" rx="12" fill="#070c10" stroke="%s"/>' % (x, y, w, h, LINE),
        '<rect x="%d" y="%d" width="%d" height="38" rx="12" fill="#111a21"/>' % (x, y, w),
        '<circle cx="%d" cy="%d" r="5" fill="#ff5f57"/>' % (x + 22, y + 19),
        '<circle cx="%d" cy="%d" r="5" fill="#febc2e"/>' % (x + 40, y + 19),
        '<circle cx="%d" cy="%d" r="5" fill="#28c840"/>' % (x + 58, y + 19),
    ]
    ty = y + 68
    for line, color in lines:
        parts.append(mono(x + 22, ty, line, 17, color))
        ty += 30
    parts.append("</g>")
    return parts


def card_one():
    parts = frame(
        "v0.1.1 · OPEN SOURCE",
        ["Prove it.", "Don't guess it."],
        [
            "Pry proves an app you own is exposed by actually",
            "trying the exploit, then captures a signed,",
            "replayable request/response pair.",
        ],
        "github.com/haqaliz/pry  ·  PyPI: pry-scanner",
    )
    parts += terminal(
        650,
        170,
        548,
        440,
        [
            ("$ pry scan ./my-app", SOFT),
            ("cors: EXPOSED", TEXT),
            ("errors: EXPOSED", TEXT),
            ("secrets: EXPOSED", TEXT),
            ("database: EXPOSED", TEXT),
            ("", TEXT),
            ("Results: ~/.pry/runs/<id>/results.json", MUTED),
            ("Report:  ~/.pry/runs/<id>/report.html", MUTED),
            ("", TEXT),
            ("A real local run.", "#28c840"),
        ],
    )
    parts.append("</svg>")
    return "\n".join(parts)


def card_two():
    parts = frame(
        "WHY PRY",
        ["The exploit", "is the verdict."],
        [
            "Most scanners say an endpoint looks risky.",
            "Pry makes the request that should have been",
            "blocked, captures what came back, and signs it.",
        ],
        "Execution decides. A heuristic may prioritize.",
    )
    boxes = [
        ("01", "Execute", "A real request against a target you own."),
        ("02", "Capture", "The exact pair, redacted and capped."),
        ("03", "Sign", "An Ed25519 bundle you can verify offline."),
    ]
    x = 72
    for num, name, body in boxes:
        parts += [
            '<rect x="%d" y="494" width="360" height="150" rx="10" fill="%s" stroke="%s"/>' % (x, PANEL, LINE),
            text(x + 22, 534, num, 15, SOFT, 600, family="Menlo, Consolas, monospace"),
            text(x + 22, 574, name, 26, TEXT, 700),
            text(x + 22, 606, body, 18, MUTED),
        ]
        # keep the body inside the card
        x += 390
    parts.append("</svg>")
    return "\n".join(parts)


def card_three():
    parts = frame(
        "PROOF",
        ["Verify it", "offline."],
        [
            "Every EXPOSED finding carries a signed bundle",
            "with the target snapshot, the redacted pair,",
            "and a fingerprint you can pin out of band.",
        ],
        "No upload. No telemetry. The proof stays local.",
    )
    parts += terminal(
        610,
        180,
        588,
        390,
        [
            ("$ pry verify-proof $PROOF", SOFT),
            ("VALID", "#28c840"),
            ("Fingerprint: sha256:e4d0ce9e...", TEXT),
            ("Probe: database", TEXT),
            ("Verdict: EXPOSED", SOFT),
            ("Target: ./my-app (node)", TEXT),
        ],
    )
    bullets = [
        "Ed25519 signed bundle",
        "Redacted request/response",
        "Read-only replay",
        "Fingerprint pinning",
    ]
    y = 500
    for item in bullets:
        parts.append(text(72, y, "✓", 22, "#28c840", 700))
        parts.append(text(104, y, item, 22, TEXT))
        y += 42
    parts.append("</svg>")
    return "\n".join(parts)


def card_four():
    parts = frame(
        "SAFETY",
        ["Ownership first.", "No 'secure' claim."],
        [
            "Live targets need DNS TXT or well-known-file",
            "proof. Read-only is the default; higher",
            "intensity needs explicit confirmation.",
        ],
        "github.com/haqaliz/pry/blob/master/ETHICS.md",
    )
    bullets = [
        "Ownership proof before any live request",
        "Local repo runs in a disposable Docker sandbox",
        "No third-party scanning. No upload.",
        "A clean result is NOT_REPRODUCED, never safe.",
    ]
    y = 500
    for item in bullets:
        parts.append(text(72, y, "✓", 22, "#28c840", 700))
        parts.append(text(104, y, item, 23, TEXT))
        y += 46
    parts.append("</svg>")
    return "\n".join(parts)


def main():
    cards = {
        "01-hero.svg": card_one(),
        "02-wedge.svg": card_two(),
        "03-proof.svg": card_three(),
        "04-safety.svg": card_four(),
    }
    for name, svg in cards.items():
        svg_path = GALLERY / name
        png_path = svg_path.with_suffix(".png")
        svg_path.write_text(svg, encoding="utf-8")
        subprocess.run(
            ["rsvg-convert", "-w", str(W), "-h", str(H), str(svg_path), "-o", str(png_path)],
            check=True,
        )
        print("wrote", png_path)


if __name__ == "__main__":
    main()
