"""End-to-end checks of the image pipeline (no Discord needed): python test_images.py"""
import io
import sqlite3
import tempfile
import time
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from scambot import attachments, imaging
from scambot.decision import decide, score_text
from scambot.learner import Learner

FONT = ImageFont.truetype("arial.ttf", 40)
learner = Learner(sqlite3.connect(":memory:"))


def card(lines: list[str], size=(900, 320), bg="white", fg="black") -> Image.Image:
    img = Image.new("RGB", size, bg)
    d = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        d.text((30, 30 + i * 60), line, fill=fg, font=FONT)
    return img


def to_bytes(img: Image.Image | list[Image.Image], fmt: str) -> bytes:
    buf = io.BytesIO()
    if isinstance(img, list):
        img[0].save(buf, fmt, save_all=True, append_images=img[1:], duration=800, loop=0)
    else:
        img.save(buf, fmt)
    return buf.getvalue()


def run(name: str, data: bytes, filename: str = "image.png") -> int:
    t0 = time.time()
    findings = attachments.check_filename(filename) + attachments.check_image_bytes(data)
    fr = imaging.load_frames(data)
    # Same early stop as the bot: stop reading frames once the text alone reaches the threshold.
    text, qrs, _ = imaging.read_frames(fr.frames, lambda t: score_text(t)[0] >= 50) if fr else ("", [], 0)
    for q in qrs:
        text += "\n" + q
        findings.append((f"QR code in image -> {q[:80]}", 15))
    d = decide(text, None, fr.hashes if fr else [], 50, learner.prob_scam(text) if text else None, 40, findings)
    frames = len(fr.frames) if fr else 0
    print(f"{d.score:>4} {'SCAM' if d.is_scam else 'ok  '} {name} [{frames} frame(s) read, {time.time() - t0:.1f}s]")
    print("      text:", text.replace("\n", " | ")[:160] or "(none)")
    print("      why:", "; ".join(d.matches)[:200])
    return d.score


scores = {}
# Scam message split across GIF frames: no single frame is enough on its own.
scores["gif"] = run("animated GIF, scam split over 3 frames", to_bytes([
    card(["Congratulations!", "You have been selected"]),
    card(["Claim your free Nitro gift", "before it expires"]),
    card(["Login here:", "discord-nitro.gift/claim"]),
], "GIF"), "nitro.gif")

# Your case: a long meme, then a MrBeast scam that slides in (tween) for under a second, then the meme again.
def meme(i):
    img = Image.new("RGB", (900, 320), (40 + i * 3 % 60, 90, 160))
    ImageDraw.Draw(img).ellipse([300 + i * 4, 60, 520 + i * 4, 280], fill=(250, 200, 60))  # moving shape, no text
    return img

def scam_tween(step, steps):
    img = Image.new("RGB", (900, 320), (15, 15, 15))
    x = 900 - int(870 * min(1.0, (step + 1) / steps))  # text slides in from the right
    d = ImageDraw.Draw(img)
    for i, line in enumerate(["MrBeast GIVEAWAY: first 1000 people", "get $500, claim your prize now",
                              "at mrbeast-gift.top"]):
        d.text((x, 40 + i * 70), line, fill="white", font=FONT)
    return img

mixed = [meme(i) for i in range(40)] + [scam_tween(i, 5) for i in range(5)] + [scam_tween(4, 5)] * 2 \
    + [meme(i) for i in range(40, 80)]
scores["mixed_gif"] = run("meme GIF with a 0.7s MrBeast tween in the middle (87 frames)", to_bytes(mixed, "GIF"),
                          "funny.gif")

# Same thing as a video, the way Discord's GIF picker (Tenor) sends it.
vid_path = Path(tempfile.mkdtemp()) / "tenor.mp4"
vw = cv2.VideoWriter(str(vid_path), cv2.VideoWriter_fourcc(*"mp4v"), 10, (900, 320))
for f in mixed:
    vw.write(cv2.cvtColor(np.array(f), cv2.COLOR_RGB2BGR))
vw.release()
scores["mixed_mp4"] = run("same thing as an MP4 (Tenor-style GIF)", vid_path.read_bytes(), "tenor.mp4")

# QR code that is really a Discord login code.
qr = cv2.QRCodeEncoder.create().encode("https://discord.com/ra/abc123xyz")
qr_img = Image.fromarray(cv2.resize(qr, (400, 400), interpolation=cv2.INTER_NEAREST)).convert("RGB")
canvas = Image.new("RGB", (900, 520), "white")
canvas.paste(qr_img, (20, 100))
ImageDraw.Draw(canvas).text((450, 200), "Scan to verify", fill="black", font=FONT)
scores["qr"] = run("Discord login QR code", to_bytes(canvas, "PNG"))

# Fake Amazon fine screenshot, dark-mode style.
scores["amazon"] = run("fake fine screenshot (dark mode)", to_bytes(card([
    "ATTENTION: You have been fined $85.22",
    "for failing to return Order No. #23442314.",
    "Please log in below within 48 hours",
    "https://shorturl.at/hlMNT"], size=(900, 300), bg="#202225", fg="white"), "PNG"))

# Malicious files.
scores["exe_as_png"] = run("Windows program renamed to .png", b"MZ\x90\x00" + b"\x00" * 500, "cute_cat.png")
scores["double_ext"] = run("double extension", b"MZ", "photo.png.exe")
scores["appended"] = run("PNG with a ZIP glued on the end",
                         to_bytes(card(["just a meme"]), "PNG") + b"PK\x03\x04" + b"\x00" * 200)

# Clean images must stay clean.
scores["clean1"] = run("normal screenshot", to_bytes(card(["gg everyone, that was a close match",
                                                            "same time tomorrow?"]), "PNG"))
scores["clean2"] = run("meme GIF", to_bytes([card(["when the code works"]), card(["first try"])], "GIF"), "meme.gif")
scores["clean3"] = run("photo with no text", to_bytes(Image.effect_noise((600, 400), 60).convert("RGB"), "JPEG"),
                       "photo.jpg")

for k in ("gif", "mixed_gif", "mixed_mp4", "qr", "amazon", "exe_as_png", "double_ext", "appended"):
    assert scores[k] >= 50, k
for k in ("clean1", "clean2", "clean3"):
    assert scores[k] < 50, k
print("ok")
