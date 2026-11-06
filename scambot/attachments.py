"""Checks on the attached files themselves, independent of what the picture says.

Each check returns (label, points). 100 points is an instant verdict.
"""
import re

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".avif", ".heic", ".svg"}
DOC_EXT = IMAGE_EXT | {".pdf", ".doc", ".docx", ".txt", ".mp4", ".mov", ".mp3"}
EXEC_EXT = {".exe", ".scr", ".com", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".hta", ".lnk", ".jar", ".apk", ".dll", ".cpl", ".pif", ".reg", ".sh", ".app", ".dmg"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"}

# File signatures that should never be inside something named like a picture.
_MAGIC = [
    (b"MZ", "Windows program (.exe)"),
    (b"\x7fELF", "Linux program"),
    (b"\xcf\xfa\xed\xfe", "macOS program"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!\x1a", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"),
    (b"<html", "web page"),
    (b"<!doctype html", "web page"),
]
# Signs of a second file glued onto the end of a real image.
_HIDDEN = [b"PK\x03\x04", b"Rar!\x1a", b"7z\xbc\xaf", b"MZ\x90\x00", b"<script", b"powershell", b"This program cannot"]
_SVG_SCRIPT = re.compile(rb"<script|\bon(load|error|click|mouseover)\s*=|javascript:|<foreignobject", re.I)


def _ext(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def check_filename(name: str) -> list[tuple[str, int]]:
    lower = name.lower()
    ext = _ext(lower)
    if "‮" in name:
        return [("filename uses a hidden right-to-left trick to fake its extension", 100)]
    if ext in EXEC_EXT:
        inner = lower.rsplit(".", 1)[0]
        if _ext(inner) in DOC_EXT:
            return [(f"double extension disguise ({_ext(inner)}{ext})", 100)]
        return [(f"executable attachment ({ext})", 60)]
    if ext in ARCHIVE_EXT:
        return [(f"archive attachment ({ext})", 15)]
    return []


def check_image_bytes(data: bytes) -> list[tuple[str, int]]:
    head = data[:64].lower()
    for magic, label in _MAGIC:
        if head.startswith(magic.lower()):
            return [(f"file looks like an image but is actually a {label}", 100)]
    if b"<svg" in data[:2048].lower() and _SVG_SCRIPT.search(data):
        return [("SVG image contains script code", 80)]
    end = None
    if data.startswith(b"\x89PNG"):
        i = data.rfind(b"IEND")
        end = i + 8 if i != -1 else None
    elif data.startswith(b"\xff\xd8"):
        i = data.rfind(b"\xff\xd9")
        end = i + 2 if i != -1 else None
    if end is not None:
        trailer = data[end:]
        if len(trailer) > 64 and any(sig in trailer for sig in _HIDDEN):
            return [("hidden file appended inside the image", 70)]
    return []
