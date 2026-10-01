#!/usr/bin/env python3
"""Generate the PWA icons referenced by manifest.json.

Why this exists: the manifest previously referenced its icon as a
``data:image/svg+xml,...`` URL. Chrome (and Safari) refuse data: URLs for
manifest icons, so the "Add to home screen" prompt never appeared and the app
was not installable. A real, same-origin PNG file is required.

The design deliberately mirrors the page palette (GitHub dark):
    background  #0d1117
    accent      #58a6ff

Run manually after changing the design:

    python tools/make_icons.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

BG = (13, 17, 23, 255)  # #0d1117
FG = (88, 166, 255, 255)  # #58a6ff

REPO_ROOT = Path(__file__).resolve().parent.parent
SIZES = (192, 512)
MASKABLE_SIZE = 512
# Rendered at 4x then downsampled with LANCZOS for clean antialiased edges.
SUPERSAMPLE = 4


def _glyph(img: Image.Image) -> None:
    """Draw the key glyph onto ``img`` (already sized/backgrounded).

    The glyph occupies the central ~60% of the canvas so that a maskable icon
    keeps its content inside the 80% safe zone Android applies.
    """
    scale = img.size[0]
    d = ImageDraw.Draw(img)
    cx = scale / 2
    stroke = int(scale * 0.08)

    bow_cy = scale * 0.30
    bow_r = scale * 0.16  # radius of the stroke centreline
    d.ellipse(
        [cx - bow_r, bow_cy - bow_r, cx + bow_r, bow_cy + bow_r],
        outline=FG,
        width=stroke,
    )

    # Start the shaft just inside the bow's lower stroke so it joins seamlessly
    # without ever crossing the bow's hole.
    shaft_top = bow_cy + bow_r * 0.6
    shaft_bottom = scale * 0.86
    d.line([(cx, shaft_top), (cx, shaft_bottom)], fill=FG, width=stroke)

    # Two teeth on the right of the shaft: short then long, both well below the
    # bow so they stay legible at 192px.
    shaft_len = shaft_bottom - shaft_top
    tooth_w = int(scale * 0.07)
    for frac, length in ((0.45, 0.10), (0.72, 0.14)):
        y = shaft_top + shaft_len * frac
        d.line(
            [(cx + stroke / 2, y), (cx + stroke / 2 + scale * length, y)],
            fill=FG,
            width=tooth_w,
        )


def draw_icon(size: int) -> Image.Image:
    """Standard icon: rounded square with a small transparent margin."""
    scale = size * SUPERSAMPLE
    img = Image.new("RGBA", (scale, scale), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    inset = int(scale * 0.06)
    d.rounded_rectangle(
        [inset, inset, scale - inset, scale - inset],
        radius=int(scale * 0.22),
        fill=BG,
    )
    _glyph(img)
    return img.resize((size, size), Image.LANCZOS)


def draw_maskable(size: int) -> Image.Image:
    """Maskable icon: opaque full bleed so Android's mask never clips a corner."""
    scale = size * SUPERSAMPLE
    img = Image.new("RGBA", (scale, scale), BG)

    # Shrink the glyph into the safe zone, then composite it onto the full-bleed
    # background. The glyph is rendered small and upscaled to the supersampled
    # canvas so it stays centred before the final downsample.
    glyph_size = int(scale * 0.62)
    glyph = Image.new("RGBA", (glyph_size, glyph_size), (0, 0, 0, 0))
    _glyph(glyph)
    glyph = glyph.resize((scale, scale), Image.LANCZOS)
    img.alpha_composite(glyph, ((scale - glyph_size) // 2, (scale - glyph_size) // 2))
    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    written = []
    for size in SIZES:
        out = REPO_ROOT / f"icon-{size}.png"
        draw_icon(size).save(out, format="PNG", optimize=True)
        written.append(out)

    maskable = REPO_ROOT / f"icon-maskable-{MASKABLE_SIZE}.png"
    draw_maskable(MASKABLE_SIZE).save(maskable, format="PNG", optimize=True)
    written.append(maskable)

    for path in written:
        print(f"wrote {path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
