import io
import sqlite3
from dataclasses import dataclass

import imagehash
import numpy as np
from PIL import Image, ImageFilter, ImageOps

MIN_SIDE = 100  # skip emoji / icons / tiny images
MAX_SCENES = 12  # most frames OCR'd per GIF/video (the most text-like scenes win)
STALE_FRAMES = 3  # stop reading a GIF/video after this many frames in a row with no new text
MAX_DECODE = 900  # frames looked at per GIF before skipping evenly
SCENE_CHANGE = 0.015  # share of pixels that must change (vs the scene's first frame) to start a new scene
VIDEO_FPS = 6  # frames per second sampled from videos
VIDEO_MAX_SECONDS = 90
SAME_FRAME_DIST = 4  # frames this close are treated as the same picture
MIN_CONFIDENCE = 0.5  # drop OCR pieces the engine is unsure about

_ocr = None
_qr = None


@dataclass
class Frames:
    frames: list[Image.Image]
    hashes: list[str]
    animated: bool


def _flatten(frame: Image.Image) -> Image.Image:
    """Put transparent pixels on white so dark text on transparent GIFs stays readable."""
    rgba = frame.convert("RGBA")
    bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(bg, rgba).convert("RGB")


def _small(img: Image.Image) -> np.ndarray:
    """Greyscale copy 200px wide (aspect kept, so wide GIFs' text isn't squashed) for comparing frames."""
    h = max(8, round(img.height * 200 / img.width))
    return np.asarray(img.convert("L").resize((200, h)), dtype=np.float32) / 255


def _changed(a: np.ndarray, b: np.ndarray) -> float:
    """Share of pixels that clearly changed. Swapping text on a plain background changes few pixels but
    changes them a lot, so count them instead of averaging the difference."""
    return float((np.abs(a - b) > 0.25).mean())


def _textiness(img: Image.Image) -> float:
    """Share of sharp edges: text-heavy frames score high, photos, memes and flat colours low.
    Measured at 480px wide (aspect kept) so small UI text in screenshots still counts, after a median
    filter so video grain and noise don't look like text."""
    h = max(8, round(img.height * 480 / img.width))
    g = np.asarray(img.convert("L").resize((480, h)).filter(ImageFilter.MedianFilter(3)), dtype=np.float32) / 255
    return float((np.abs(np.diff(g, axis=1)) > 0.12).mean() + (np.abs(np.diff(g, axis=0)) > 0.12).mean())


def pick_scenes(frames) -> list[Image.Image]:
    """Split an animation into scenes and keep the LAST frame of each one, so text that slides or fades in
    (a tween) is read once it has fully appeared. A scene shown for a split second still gets its own frame."""
    scenes: list[list] = []  # [first frame (small), last frame]
    for f in frames:
        s = _small(f)
        if not scenes or _changed(s, scenes[-1][0]) > SCENE_CHANGE:
            scenes.append([s, f])
        else:
            scenes[-1][1] = f
    picked = [last for _, last in scenes]
    if len(picked) > MAX_SCENES:
        # Too many scenes to OCR them all: always keep the opening scene (the "flash a scam, then cover it
        # with a meme" trick puts it there), then the most text-like of the rest, in their original order.
        rest = sorted(range(1, len(picked)), key=lambda i: -_textiness(picked[i]))[:MAX_SCENES - 1]
        picked = [picked[i] for i in sorted([0] + rest)]
    return picked


def _gif_frames(img: Image.Image):
    n = getattr(img, "n_frames", 1)
    step = max(1, n // MAX_DECODE)
    for i in range(0, n, step):
        img.seek(i)
        yield _flatten(img)


def is_video(data: bytes) -> bool:
    """MP4/MOV ("ftyp" box) or WebM/MKV (EBML header)."""
    return data[4:8] == b"ftyp" or data.startswith(b"\x1a\x45\xdf\xa3")


def _video_frames(data: bytes):
    """Decode a video (Tenor/Giphy "GIFs" are really MP4s) with OpenCV, sampling VIDEO_FPS frames per second."""
    import os
    import tempfile

    import cv2
    fd, path = tempfile.mkstemp(suffix=".mp4")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        cap = cv2.VideoCapture(path)
        fps = cap.get(cv2.CAP_PROP_FPS) or 30
        step = max(1, round(fps / VIDEO_FPS))
        i = 0
        while i < fps * VIDEO_MAX_SECONDS:
            ok, frame = cap.read()
            if not ok:
                break
            if i % step == 0:
                yield Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            i += 1
        cap.release()
    finally:
        os.remove(path)


def load_frames(data: bytes) -> Frames | None:
    """Decode an image, GIF or video and return its distinct frames worth reading."""
    try:
        try:
            img = Image.open(io.BytesIO(data))
            animated = getattr(img, "n_frames", 1) > 1
            candidates = pick_scenes(_gif_frames(img)) if animated else [_flatten(ImageOps.exif_transpose(img))]
        except Exception:
            if not is_video(data):
                return None
            candidates = pick_scenes(_video_frames(data))
            animated = True
        frames, hashes, smalls = [], [], []
        for f in candidates:
            if min(f.size) < MIN_SIDE:
                continue
            # Skip true repeats (e.g. a GIF that loops back to an earlier scene). Compared by changed pixels,
            # not by hash: cards with different text on the same background have nearly identical hashes.
            s = _small(f)
            if any(_changed(s, o) <= SCENE_CHANGE for o in smalls):
                continue
            frames.append(f)
            smalls.append(s)
            h = phash_hex(f)
            if not any(_dist(h, k) == 0 for k in hashes):
                hashes.append(h)
    except Exception:
        return None
    return Frames(frames, hashes, animated) if frames else None


def preview_png(img: Image.Image, max_side: int = 800) -> bytes:
    """A clean re-encoded copy for showing the user what was removed (drops anything hidden in the file)."""
    img = img.copy()
    img.thumbnail((max_side, max_side))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def phash_hex(img: Image.Image) -> str:
    return str(imagehash.phash(img, hash_size=8))


def _ocr_ready_size(img: Image.Image) -> Image.Image:
    """OCR misses small text and is slow on huge images; aim for ~1000-2400px on the long side."""
    long_side = max(img.size)
    scale = 1000 / long_side if long_side < 1000 else 2400 / long_side if long_side > 2400 else 1
    scale = min(scale, 3)
    if scale == 1:
        return img
    return img.resize((round(img.width * scale), round(img.height * scale)), Image.Resampling.LANCZOS)


def ocr_lines(img: Image.Image) -> list[str]:
    """OCR one picture and return its text lines in reading order (top-to-bottom, left-to-right)."""
    global _ocr
    if _ocr is None:
        from rapidocr import RapidOCR
        _ocr = RapidOCR()
    result = _ocr(np.array(_ocr_ready_size(img)))
    # The full pipeline returns RapidOCROutput; getattr keeps the type checker happy with its union type.
    txts, boxes = getattr(result, "txts", None), getattr(result, "boxes", None)
    if not txts or boxes is None:
        return []
    scores = getattr(result, "scores", None) or [1.0] * len(txts)
    pieces = []
    for box, txt, score in zip(boxes, txts, scores):
        if score < MIN_CONFIDENCE or not txt.strip():
            continue
        ys, xs = box[:, 1], box[:, 0]
        pieces.append((float(ys.mean()), float(xs.min()), float(ys.max() - ys.min()), txt.strip()))
    # Group pieces whose vertical centres are close into one row, then read each row left to right.
    pieces.sort()
    rows: list[list[tuple[float, float, float, str]]] = []
    for p in pieces:
        if rows and abs(p[0] - rows[-1][0][0]) < 0.6 * max(p[2], rows[-1][0][2]):
            rows[-1].append(p)
        else:
            rows.append([p])
    return [" ".join(t for _, _, _, t in sorted(r, key=lambda q: q[1])) for r in rows]


def qr_codes(img: Image.Image) -> list[str]:
    global _qr
    try:
        import cv2
        if _qr is None:
            _qr = cv2.QRCodeDetector()
        ok, decoded, _, _ = _qr.detectAndDecodeMulti(np.array(img))
        return [d for d in decoded if d] if ok else []
    except Exception:
        return []


def _key(line: str) -> str:
    return "".join(ch for ch in line.lower() if ch.isalnum())


def _assemble(per_frame: dict[int, list[str]]) -> str:
    """Join frame texts in playback order, dropping repeats and the partial lines of text sliding or typing in
    (e.g. "MrBeast GIVEAWA" when "MrBeast GIVEAWAY: first 1000 people" was also read)."""
    lines = [l for i in sorted(per_frame) for l in per_frame[i] if _key(l)]
    keys = [_key(l) for l in lines]
    out, seen = [], set()
    for line, k in zip(lines, keys):
        if k in seen or any(k != other and k in other for other in keys):
            continue
        seen.add(k)
        out.append(line)
    return "\n".join(out)


def read_frames(frames: list[Image.Image], enough=None) -> tuple[str, list[str], int]:
    """Piece together the text of every frame plus any QR code contents.

    The opening frame is read first (the "flash a scam, then cover it with a meme" trick puts it there), then
    the most text-like frames. Reading stops early once `enough(text)` says the verdict is certain, or once
    STALE_FRAMES frames in a row add no new text (e.g. a meme with the same caption in every scene). The text
    is still assembled in playback order. Also returns the index of the frame with the most text: the best
    one to show moderators and the user."""
    rest = sorted(range(1, len(frames)), key=lambda i: -_textiness(frames[i]))
    order = [0] + rest if frames else []
    per_frame: dict[int, list[str]] = {}
    qrs: list[str] = []
    seen: set[str] = set()
    best, best_len, stale = 0, -1, 0
    for i in order:
        per_frame[i] = ocr_lines(frames[i])
        n = sum(len(l) for l in per_frame[i])
        if n > best_len:
            best, best_len = i, n
        new_qr = [q for q in qr_codes(frames[i]) if q not in qrs]
        qrs += new_qr
        if enough and enough("\n".join([_assemble(per_frame)] + qrs)):
            break
        # Count a line as new unless it (or a longer version of it) was already read.
        keys = {_key(l) for l in per_frame[i] if _key(l)}
        fresh = {k for k in keys if not any(k in s for s in seen)}
        seen |= keys
        stale = 0 if (fresh or new_qr) else stale + 1
        if stale >= STALE_FRAMES:
            break
    return _assemble(per_frame), qrs, best


class HashStore:
    """Known-scam perceptual hashes, persisted in SQLite and cached in memory."""

    def __init__(self, path: str = "scam_hashes.db"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS hashes (hash TEXT PRIMARY KEY, note TEXT, added TEXT DEFAULT CURRENT_TIMESTAMP)"
        )
        self.db.commit()
        self.cache = {h: n for h, n in self.db.execute("SELECT hash, note FROM hashes")}

    def add(self, h: str, note: str = "") -> bool:
        if h in self.cache:
            return False
        self.cache[h] = note
        self.db.execute("INSERT OR IGNORE INTO hashes (hash, note) VALUES (?, ?)", (h, note))
        self.db.commit()
        return True

    def remove_near(self, h: str, max_distance: int) -> int:
        victims = [k for k in self.cache if _dist(k, h) <= max_distance]
        for k in victims:
            del self.cache[k]
            self.db.execute("DELETE FROM hashes WHERE hash = ?", (k,))
        self.db.commit()
        return len(victims)

    def match(self, h: str, max_distance: int) -> str | None:
        for known, note in self.cache.items():
            if _dist(known, h) <= max_distance:
                return note or known
        return None


def _dist(a: str, b: str) -> int:
    return (int(a, 16) ^ int(b, 16)).bit_count()
