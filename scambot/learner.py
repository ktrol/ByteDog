"""A small naive Bayes text classifier that learns from moderator feedback.

Every labeled example (seed, moderator button, auto-learned high-confidence scam,
or sampled normal chat) is stored in SQLite, so learning survives restarts.
"""
import json
import math
import re
import sqlite3
from collections import Counter

from .rules import normalize
from .seeds import SEED_HAM, SEED_SCAM

HAM, SCAM = 0, 1
MIN_PER_CLASS = 20  # model stays off until it has this many examples of each label

_URL = re.compile(r"https?://\S+|\b[\w-]+\.(com|net|org|gg|xyz|top|click|link|ru|io|co|me|at|ly|site|shop)\b\S*")
_TOK = re.compile(r"<url>|<num>|\$|%|[a-z][a-z']+")


def tokenize(text: str) -> set[str]:
    t = _URL.sub(" <url> ", normalize(text))
    t = re.sub(r"\d[\d,.]*", " <num> ", t)
    words = _TOK.findall(t)
    return set(words) | {f"{a}_{b}" for a, b in zip(words, words[1:])}


class Learner:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        db.executescript("""
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY, text TEXT, label INTEGER, source TEXT,
                detection_id INTEGER, added TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY, guild_id INTEGER, user_id INTEGER, text TEXT,
                hashes TEXT, score INTEGER, added TEXT DEFAULT CURRENT_TIMESTAMP);
        """)
        cols = {r[1] for r in db.execute("PRAGMA table_info(detections)")}
        for col, typ in (("rule_labels", "TEXT"), ("channel_id", "INTEGER"), ("message_id", "INTEGER")):
            if col not in cols:  # upgrade databases created by older versions
                db.execute(f"ALTER TABLE detections ADD COLUMN {col} {typ}")
        if not db.execute("SELECT 1 FROM samples WHERE source = 'seed' LIMIT 1").fetchone():
            db.executemany("INSERT INTO samples (text, label, source) VALUES (?, ?, 'seed')",
                           [(t, SCAM) for t in SEED_SCAM] + [(t, HAM) for t in SEED_HAM])
        db.commit()
        self.retrain()

    # ------------------------------------------------------------ training
    def retrain(self):
        self.counts = [Counter(), Counter()]
        self.docs = [0, 0]
        for text, label in self.db.execute("SELECT text, label FROM samples"):
            self._learn(text, label)

    def _learn(self, text: str, label: int):
        self.counts[label].update(tokenize(text))
        self.docs[label] += 1

    def add(self, text: str, label: int, source: str, detection_id: int | None = None):
        if len(text.split()) < 3:
            return
        self.db.execute("INSERT INTO samples (text, label, source, detection_id) VALUES (?, ?, ?, ?)",
                        (text[:4000], label, source, detection_id))
        self.db.commit()
        self._learn(text, label)

    def relabel_detection(self, detection_id: int, label: int, source: str):
        """Moderator verdict on a detection: replace any earlier label for it."""
        det = self.get_detection(detection_id)
        if not det:
            return
        self.db.execute("DELETE FROM samples WHERE detection_id = ?", (detection_id,))
        if len(det["text"].split()) >= 3:  # images with no readable text have nothing to teach the text model
            self.db.execute("INSERT INTO samples (text, label, source, detection_id) VALUES (?, ?, ?, ?)",
                            (det["text"][:4000], label, source, detection_id))
        self.db.commit()
        self.retrain()

    # ----------------------------------------------------------- inference
    @property
    def ready(self) -> bool:
        return min(self.docs) >= MIN_PER_CLASS

    def prob_scam(self, text: str) -> float | None:
        """P(scam) using Bernoulli-style counts and equal priors (so lots of sampled
        normal chat doesn't drown out the scam class)."""
        if not self.ready:
            return None
        toks = [t for t in tokenize(text) if t in self.counts[0] or t in self.counts[1]]
        if len(toks) < 3:
            return None
        log_odds = 0.0
        for t in toks:
            p_scam = (self.counts[SCAM][t] + 1) / (self.docs[SCAM] + 2)
            p_ham = (self.counts[HAM][t] + 1) / (self.docs[HAM] + 2)
            log_odds += math.log(p_scam / p_ham)
        log_odds /= math.sqrt(len(toks))  # damp overconfidence on long texts
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, log_odds))))

    # ---------------------------------------------------------- detections
    def record_detection(self, guild_id: int, user_id: int, text: str, hashes: list[str], score: int,
                         rule_labels: list[str], channel_id: int, message_id: int) -> int:
        cur = self.db.execute(
            "INSERT INTO detections (guild_id, user_id, text, hashes, score, rule_labels, channel_id, message_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (guild_id, user_id, text[:4000], json.dumps(hashes), score, json.dumps(rule_labels), channel_id,
             message_id))
        self.db.commit()
        return cur.lastrowid or 0

    def get_detection(self, detection_id: int) -> dict | None:
        row = self.db.execute("SELECT guild_id, user_id, text, hashes, rule_labels, channel_id, message_id "
                              "FROM detections WHERE id = ?", (detection_id,)).fetchone()
        if not row:
            return None
        return {"guild_id": row[0], "user_id": row[1], "text": row[2], "hashes": json.loads(row[3]),
                "rule_labels": json.loads(row[4] or "[]"), "channel_id": row[5], "message_id": row[6]}

    def stats(self) -> dict:
        by_source = dict(self.db.execute(
            "SELECT source || ':' || CASE label WHEN 1 THEN 'scam' ELSE 'normal' END, COUNT(*) "
            "FROM samples GROUP BY 1").fetchall())
        return {"scam": self.docs[SCAM], "normal": self.docs[HAM], "ready": self.ready, "by_source": by_source}
