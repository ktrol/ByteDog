"""Checks the extra learning methods: python test_memory.py"""
import shutil
import sqlite3
import tempfile
from pathlib import Path

from scambot.decision import decide, score_text
from scambot.learner import Learner
from scambot.memory import Memory, extract_links

mem = Memory(sqlite3.connect(":memory:"))

# 1. Scam links: learned from a confirmed scam, then flag a different image using the same site.
assert extract_links("visit https://www.free-gifts-now.top/claim or shorturl.at/hlMNT, discord.gg/abc") == \
    {"free-gifts-now.top", "shorturl.at/hlmnt"}
mem.learn_scam("Claim your reward at free-gifts-now.top today", [], "test")
f = mem.check("New event!! Go to free-gifts-now.top for prizes")
print("links:", f)
assert any("known scam site" in x for x, _ in f)
assert not mem.check("check out youtube.com and discord.gg/abc")

# 2. Templates: same wording on a different image is caught, unrelated text is not.
scam = "Hello I am from the Discord staff team your account was reported for breaking the rules please contact us now"
mem.learn_scam(scam, [], "test")
f = mem.check("hello i am from the discord staff team. your account was reported for breaking the rules, contact us")
print("template:", f)
assert any(pts == 100 for _, pts in f)
assert not mem.check("hello everyone, the event is starting soon, join the voice channel for the team game")

# 3. Rule reliability: a rule that keeps being wrong loses weight; one that keeps being right gains.
for _ in range(4):
    mem.learn_ham("the attention everyone", ["alarm header"])
    mem.learn_scam("x", ["free Nitro"], "test")
print("multipliers:", mem.rule_multiplier("alarm header"), mem.rule_multiplier("free Nitro"))
assert mem.rule_multiplier("alarm header") < 0.7 and mem.rule_multiplier("free Nitro") > 1.3
base, _, _ = score_text("ATTENTION: free nitro")
tuned, matches, _ = score_text("ATTENTION: free nitro", mem.rule_multiplier)
print("scores:", base, "->", tuned, matches)
assert tuned > base

# 4. "Not a scam" undoes a learned link/template.
mem.learn_ham("Claim your reward at free-gifts-now.top today", [])
assert not any("known scam site" in x for x, _ in mem.check("free-gifts-now.top"))

# 5. Spam waves: same image in 3 channels by one user.
h = "ad2bdad0b4d0d2c3"
mem.remember_post(1, 42, 100, [h], "", 0)
mem.remember_post(1, 42, 101, [h], "", 0)
f = mem.wave(1, 42, 102, [h], 6)
print("wave:", f)
assert any("3 channels" in x for x, _ in f)
assert not mem.wave(1, 99, 100, ["0f0f0f0f0f0f0f0f"], 6)

# 6. Upgrading the real database works (tables and columns get added).
real = Path("scam_hashes.db")
if real.exists():
    tmp = Path(tempfile.mkdtemp()) / "copy.db"
    shutil.copy(real, tmp)
    db = sqlite3.connect(tmp)
    Learner(db)
    Memory(db)
    cols = {r[1] for r in db.execute("PRAGMA table_info(detections)")}
    assert {"rule_labels", "channel_id", "message_id"} <= cols, cols
    db.close()
    print("database upgrade: ok")

d = decide("free nitro claim your gift", None, [], 50, None, 40, mem.check("free nitro"), mem.rule_multiplier)
print("decision with learned weights:", d.score, d.rule_labels)
print("ok")
