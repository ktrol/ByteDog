"""Extra things the bot learns from confirmed scams and mistakes, beyond image hashes and the text model:

- scam links/domains (scammers reuse them across many images)
- scam text templates (same wording on a new background still matches)
- how reliable each phrase rule is in this server (weights adjust over time)
- recent posts, to spot spam waves and to learn from bans
"""
import json
import re
import sqlite3
import time
from collections import deque

from .imaging import _dist
from .rules import normalize

_TLDS = ("com|net|org|gg|xyz|top|click|link|site|online|shop|store|app|io|co|me|ru|cn|tk|ml|ga|cf|gq|info|biz|"
         "live|gift|pro|vip|icu|cfd|sbs|rest|monster|win|bid|lol|fun|space|website|tech|us|uk|at|ly|to|cc|ws|su|pw|"
         "ee|in|de|fr|xxx|cam|claims?|support|help|login|bond|today|world")
_DOMAIN = re.compile(rf"\b((?:[a-z0-9-]+\.)+(?:{_TLDS}))\b(/[\w-]+)?")
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "t.ly", "t.co", "tiny.cc",
              "goo.su", "clck.ru", "t.me", "wa.me"}
ALLOWED = {"discord.com", "discord.gg", "discordapp.com", "discord.gift", "discord.new", "youtube.com", "youtu.be",
           "google.com", "twitch.tv", "tenor.com", "giphy.com", "imgur.com", "github.com", "twitter.com", "x.com",
           "reddit.com", "steamcommunity.com", "steampowered.com", "amazon.com", "paypal.com", "roblox.com",
           "epicgames.com", "microsoft.com", "apple.com", "spotify.com", "instagram.com", "tiktok.com"}

TEMPLATE_MIN_WORDS = 8
WAVE_WINDOW = 10 * 60  # seconds
RECENT_KEEP = 60 * 60  # keep posts for an hour (ban learning)


def extract_links(text: str) -> set[str]:
    """Domains in the text; for link shorteners keep the full short link, since the shortener itself is shared."""
    out = set()
    for m in _DOMAIN.finditer(normalize(text)):
        domain = m.group(1).removeprefix("www.")
        if domain in ALLOWED or any(domain.endswith("." + a) for a in ALLOWED):
            continue
        if domain in SHORTENERS:
            if m.group(2):
                out.add(domain + m.group(2))
        else:
            out.add(domain)
    return out


def shingles(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", normalize(text))
    return {" ".join(words[i:i + 3]) for i in range(len(words) - 2)} if len(words) >= TEMPLATE_MIN_WORDS else set()


def similarity(a: set[str], b: set[str]) -> float:
    """Share of the smaller text's 3-word phrases found in the other. Screenshots add extra text (names,
    timestamps) around a scam, so measuring overlap against the smaller side keeps those from hiding it."""
    return len(a & b) / min(len(a), len(b)) if a and b else 0.0


class Memory:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scam_links (link TEXT PRIMARY KEY, note TEXT, added TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY, text TEXT, note TEXT, added TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS rule_stats (label TEXT PRIMARY KEY, scam INTEGER DEFAULT 0, ham INTEGER DEFAULT 0);
        """)
        db.commit()
        self.links = {l: n for l, n in db.execute("SELECT link, note FROM scam_links")}
        self.templates = {i: shingles(t) for i, t in db.execute("SELECT id, text FROM templates")}
        self.rule_stats = {l: [s, h] for l, s, h in db.execute("SELECT label, scam, ham FROM rule_stats")}
        # (time, guild_id, user_id, channel_id, hashes, text, rule_score)
        self.recent: deque[tuple[float, int, int, int, list[str], str, int]] = deque()

    # ------------------------------------------------------------- checks
    def check(self, text: str) -> list[tuple[str, int]]:
        findings = []
        for link in sorted(extract_links(text) & set(self.links)):
            findings.append((f"links to a known scam site ({link})", 60))
        sh = shingles(text)
        if sh and self.templates:
            best = max(similarity(sh, t) for t in self.templates.values())
            if best >= 0.7:
                findings.append((f"same wording as a confirmed scam ({best:.0%} match)", 100))
            elif best >= 0.45:
                findings.append((f"similar wording to a confirmed scam ({best:.0%} match)", 50))
        return findings

    def rule_multiplier(self, label: str) -> float:
        """0.5x for rules that keep being wrong here, up to 1.5x for rules that keep being right."""
        s, h = self.rule_stats.get(label, (0, 0))
        if s + h < 3:
            return 1.0
        return 0.5 + (s + 1) / (s + h + 2)

    def wave(self, guild_id: int, user_id: int, channel_id: int, hashes: list[str], max_dist: int) -> list[tuple[str, int]]:
        """Same picture spread over several channels (hijacked account) or by several accounts (raid)."""
        now = time.time()
        while self.recent and now - self.recent[0][0] > RECENT_KEEP:
            self.recent.popleft()
        if not hashes:
            return []
        channels, users = {channel_id}, {user_id}
        for t, g, u, c, hs, _, _ in self.recent:
            if g != guild_id or now - t > WAVE_WINDOW:
                continue
            if any(_dist(a, b) <= max_dist for a in hashes for b in hs):
                users.add(u)
                if u == user_id:
                    channels.add(c)
        findings = []
        if len(channels) >= 3:
            findings.append((f"same image posted in {len(channels)} channels within minutes (spam / hijacked account)", 45))
        if len(users) >= 3:
            findings.append((f"same image posted by {len(users)} different accounts within minutes (spam wave)", 25))
        return findings

    def remember_post(self, guild_id: int, user_id: int, channel_id: int, hashes: list[str], text: str, rule_score: int):
        self.recent.append((time.time(), guild_id, user_id, channel_id, hashes, text, rule_score))

    def recent_from(self, guild_id: int, user_id: int) -> list[tuple[list[str], str, int]]:
        return [(hs, txt, rs) for _, g, u, _, hs, txt, rs in self.recent if g == guild_id and u == user_id]

    # ----------------------------------------------------------- learning
    def learn_scam(self, text: str, rule_labels: list[str], note: str, count_rules: bool = True):
        for link in extract_links(text):
            if link not in self.links:
                self.links[link] = note
                self.db.execute("INSERT OR IGNORE INTO scam_links (link, note) VALUES (?, ?)", (link, note))
        sh = shingles(text)
        if sh and not any(similarity(sh, t) >= 0.9 for t in self.templates.values()):
            cur = self.db.execute("INSERT INTO templates (text, note) VALUES (?, ?)", (text[:4000], note))
            self.templates[cur.lastrowid or 0] = sh
        if count_rules:
            self._count(rule_labels, 0)
        self.db.commit()

    def learn_ham(self, text: str, rule_labels: list[str]):
        """A moderator said this isn't a scam: forget its links/templates and mark its rules as less reliable."""
        for link in extract_links(text) & set(self.links):
            del self.links[link]
            self.db.execute("DELETE FROM scam_links WHERE link = ?", (link,))
        sh = shingles(text)
        for i, t in list(self.templates.items()):
            if similarity(sh, t) >= 0.45:
                del self.templates[i]
                self.db.execute("DELETE FROM templates WHERE id = ?", (i,))
        self._count(rule_labels, 1)
        self.db.commit()

    def _count(self, rule_labels: list[str], col: int):
        for label in set(rule_labels):
            st = self.rule_stats.setdefault(label, [0, 0])
            st[col] += 1
            self.db.execute("INSERT INTO rule_stats (label, scam, ham) VALUES (?, ?, ?) "
                            "ON CONFLICT(label) DO UPDATE SET scam = excluded.scam, ham = excluded.ham",
                            (label, st[0], st[1]))

    def stats(self) -> dict:
        tuned = {l: round(self.rule_multiplier(l), 2) for l in self.rule_stats if self.rule_multiplier(l) != 1.0}
        return {"links": len(self.links), "templates": len(self.templates), "tuned_rules": tuned}
