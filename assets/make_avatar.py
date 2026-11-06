"""Generates ByteDog's profile picture: python assets/make_avatar.py"""
import math
import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

S = 2048  # draw at 2x, downscale to 1024 for smooth edges
OUT = Path(__file__).with_name("bytedog_avatar.png")


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def radial_bg(size, inner, outer):
    img = Image.new("RGB", (size, size))
    px = img.load()
    c = size / 2
    for y in range(size):
        for x in range(size):
            t = min(1.0, math.hypot(x - c, y - c) / (size * 0.72))
            px[x, y] = lerp(inner, outer, t)
    return img


def shield_points(cx, top, w, h, n=80):
    """Classic shield: gently dipped top, straight sides to halfway, convex curves to a bottom point."""
    l, r = cx - w / 2, cx + w / 2
    side_end = top + h * 0.5
    pts = []
    for i in range(n + 1):  # top edge with a slight dip in the middle
        x = l + w * i / n
        pts.append((x, top + 35 * math.sin(math.pi * i / n)))
    pts.append((r, side_end))
    for i in range(1, n + 1):  # right curve: quadratic bezier with control point below the side
        t = i / n
        x = r - t * t * (r - cx)
        y = (1 - t) ** 2 * side_end + 2 * t * (1 - t) * (top + h * 0.85) + t * t * (top + h)
        pts.append((x, y))
    for i in range(n - 1, -1, -1):  # mirror up the left side
        t = i / n
        x = l + t * t * (cx - l)
        y = (1 - t) ** 2 * side_end + 2 * t * (1 - t) * (top + h * 0.85) + t * t * (top + h)
        pts.append((x, y))
    return pts


def vertical_gradient(size, top_color, bottom_color):
    g = Image.new("RGB", size)
    d = ImageDraw.Draw(g)
    for y in range(size[1]):
        d.line([(0, y), (size[0], y)], fill=lerp(top_color, bottom_color, y / size[1]))
    return g


def binary_rain(img: Image.Image, density=0.35, seed=7):
    """Faint binary "bytes" scattered over the background."""
    rnd = random.Random(seed)
    d = ImageDraw.Draw(img)
    try:
        mono = ImageFont.truetype("consola.ttf", 54)
    except OSError:
        mono = ImageFont.load_default()
    for row in range(0, img.height, 78):
        for col in range(0, img.width, 120):
            if rnd.random() < density:
                shade = rnd.randint(28, 50)
                d.text((col + rnd.randint(-10, 10), row), rnd.choice("01") + rnd.choice("01"),
                       fill=(shade, shade + 20, shade + 70), font=mono)


def badge() -> Image.Image:
    """The glowing shield + guard dog on a transparent SxS canvas."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    cx = S / 2
    top, w, h = 280, 1340, 1480
    # Glow behind the shield.
    glow = Image.new("L", (S, S), 0)
    ImageDraw.Draw(glow).polygon(shield_points(cx, top - 30, w + 60, h + 60), fill=255)
    glow = glow.filter(ImageFilter.GaussianBlur(70)).point(lambda v: int(v * 0.55))
    layer = Image.new("RGBA", (S, S), (88, 130, 255, 0))
    layer.putalpha(glow)
    img.alpha_composite(layer)

    # Shield: white rim, then gradient body.
    d = ImageDraw.Draw(img)
    d.polygon(shield_points(cx, top, w, h), fill=(240, 244, 255))
    body_mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(body_mask).polygon(shield_points(cx, top + 45, w - 90, h - 110), fill=255)
    img.paste(vertical_gradient((S, S), (88, 101, 242), (40, 52, 160)), (0, 0), body_mask)

    # Dog head (geometric, facing forward).
    d = ImageDraw.Draw(img)
    fur, fur_dark, dark = (250, 250, 255), (205, 212, 235), (22, 26, 48)
    hy = 980  # head centre y
    # Ears
    d.polygon([(cx - 330, hy - 120), (cx - 300, hy - 470), (cx - 90, hy - 230)], fill=fur)
    d.polygon([(cx + 330, hy - 120), (cx + 300, hy - 470), (cx + 90, hy - 230)], fill=fur)
    d.polygon([(cx - 285, hy - 170), (cx - 268, hy - 390), (cx - 150, hy - 235)], fill=(255, 150, 170))
    d.polygon([(cx + 285, hy - 170), (cx + 268, hy - 390), (cx + 150, hy - 235)], fill=(255, 150, 170))
    # Head and muzzle
    d.rounded_rectangle([cx - 340, hy - 280, cx + 340, hy + 230], radius=230, fill=fur)
    d.polygon([(cx - 340, hy - 20), (cx + 340, hy - 20), (cx + 170, hy + 330), (cx - 170, hy + 330)], fill=fur)
    d.ellipse([cx - 200, hy + 60, cx + 200, hy + 360], fill=fur_dark)
    # Eyes with highlights
    for sx in (-1, 1):
        ex = cx + sx * 150
        d.ellipse([ex - 62, hy - 110, ex + 62, hy + 14], fill=dark)
        d.ellipse([ex - 18 + sx * 4, hy - 88, ex + 18 + sx * 4, hy - 52], fill=(255, 255, 255))
    # Brows (alert, protective look)
    d.line([(cx - 225, hy - 170), (cx - 85, hy - 135)], fill=dark, width=34)
    d.line([(cx + 225, hy - 170), (cx + 85, hy - 135)], fill=dark, width=34)
    # Nose and mouth
    d.rounded_rectangle([cx - 85, hy + 80, cx + 85, hy + 175], radius=45, fill=dark)
    d.line([(cx, hy + 175), (cx, hy + 250)], fill=dark, width=22)
    d.arc([cx - 120, hy + 170, cx, hy + 290], 20, 160, fill=dark, width=22)
    d.arc([cx, hy + 170, cx + 120, hy + 290], 20, 160, fill=dark, width=22)

    # Collar with a check-mark tag (security / verified).
    d.rounded_rectangle([cx - 300, hy + 345, cx + 300, hy + 425], radius=40, fill=(237, 66, 69))
    d.ellipse([cx - 95, hy + 380, cx + 95, hy + 570], fill=(254, 231, 92), outline=(200, 160, 30), width=14)
    d.line([(cx - 48, hy + 478), (cx - 10, hy + 516), (cx + 55, hy + 440)], fill=dark, width=26, joint="curve")
    return img


def main():
    img = radial_bg(S // 4, (34, 52, 110), (8, 12, 30)).resize((S, S), Image.Resampling.BICUBIC).convert("RGBA")
    binary_rain(img)
    img.alpha_composite(badge())
    img.convert("RGB").resize((1024, 1024), Image.Resampling.LANCZOS).save(OUT)
    print("saved", OUT)


if __name__ == "__main__":
    main()
