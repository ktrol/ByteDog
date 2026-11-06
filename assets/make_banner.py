"""Generates ByteDog's profile banner (17:6, like Discord's 680x240): python assets/make_banner.py"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from make_avatar import badge, binary_rain, lerp

W, H = 2720, 960  # 4x Discord's 680x240, saved at 1360x480
OUT = Path(__file__).with_name("bytedog_banner.png")


def font(name, size, fallback="arial.ttf"):
    try:
        return ImageFont.truetype(name, size)
    except OSError:
        return ImageFont.truetype(fallback, size)


def main():
    # Background: deep navy, slightly brighter behind the text and badge.
    img = Image.new("RGBA", (W, H))
    d = ImageDraw.Draw(img)
    for x in range(W):
        d.line([(x, 0), (x, H)], fill=lerp((10, 14, 34), (30, 44, 100), (x / W) ** 0.8) + (255,))
    binary_rain(img, density=0.3, seed=11)

    # Badge on the right (the avatar covers the bottom-left corner of banners on Discord).
    b = badge().resize((820, 820), Image.Resampling.LANCZOS)
    img.alpha_composite(b, (W - 900, (H - 820) // 2 + 10))

    # Text block, centred in the middle of the banner.
    d = ImageDraw.Draw(img)
    title_f = font("segoeuib.ttf", 250, "arialbd.ttf")
    tag_f = font("segoeui.ttf", 72)
    chip_f = font("segoeuisb.ttf", 48, "arialbd.ttf")
    by_f = font("segoeui.ttf", 56)
    x0, y0 = 640, 150

    # Soft glow under the title.
    glow = Image.new("L", (W, H), 0)
    ImageDraw.Draw(glow).text((x0, y0), "ByteDog", font=title_f, fill=255)
    glow = glow.filter(ImageFilter.GaussianBlur(28)).point(lambda v: int(v * 0.6))
    layer = Image.new("RGBA", (W, H), (88, 130, 255, 0))
    layer.putalpha(glow)
    img.alpha_composite(layer)
    d = ImageDraw.Draw(img)
    d.text((x0, y0), "Byte", font=title_f, fill=(255, 255, 255))
    d.text((x0 + d.textlength("Byte", font=title_f), y0), "Dog", font=title_f, fill=(120, 140, 255))

    d.text((x0 + 8, y0 + 300), "Scam image & malicious file protection", font=tag_f, fill=(205, 214, 245))

    # Feature chips.
    cx, cy = x0 + 8, y0 + 430
    for label in ("Image OCR", "QR scan", "File checks", "Self-learning"):
        tw = d.textlength(label, font=chip_f)
        d.rounded_rectangle([cx, cy, cx + tw + 56, cy + 82], radius=41, fill=(88, 101, 242, 255),
                            outline=(150, 165, 255), width=4)
        d.text((cx + 28, cy + 12), label, font=chip_f, fill=(255, 255, 255))
        cx += tw + 56 + 28

    d.text((x0 + 8, y0 + 560), "by Concept Bytes", font=by_f, fill=(140, 150, 190))

    img.convert("RGB").resize((W // 2, H // 2), Image.Resampling.LANCZOS).save(OUT)
    print("saved", OUT)


if __name__ == "__main__":
    main()
