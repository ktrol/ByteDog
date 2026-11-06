from collections.abc import Callable
from dataclasses import dataclass, field

from .rules import RULES, normalize

# Short names for the one-line verdict, e.g. "Scam (Nitro) detected".
CATEGORY_NAMES = {
    "crypto": "Crypto", "job": "Fake job", "invest": "Investment", "gift": "Giveaway", "phish": "Phishing",
    "contact": "Off-platform", "url": "Domain", "billing": "Billing", "account": "Account takeover",
    "malware": "Malware", "adult": "NSFW lure", "extortion": "Sextortion", "money": "Money",
    "techsupport": "Tech support",
}
_RULE_CATEGORY = {label: cat for cat, _, _, label in RULES}
MALICIOUS_FILE = "Malicious file"


def finding_category(label: str) -> str:
    if "known scam site" in label:
        return "Domain"
    if "wording" in label:
        return "Known scam"
    if "QR code" in label:
        return "QR code"
    if "posted in" in label or "posted by" in label:
        return "Spam wave"
    return MALICIOUS_FILE  # everything else comes from the attachment checks


def headline(category: str) -> str:
    return "Malicious file detected" if category == MALICIOUS_FILE else f"Scam ({category}) detected"


@dataclass
class Decision:
    is_scam: bool
    score: int = 0
    reason: str = "no scam detected"
    matches: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    known_match: bool = False
    text: str = ""
    rule_score: int = 0
    rule_labels: list[str] = field(default_factory=list)  # which phrase rules fired (for reliability learning)
    category: str = ""  # the biggest single contributor, for the short verdict
    signals: list[str] = field(default_factory=list)  # short reasons, strongest first

    @property
    def headline(self) -> str:
        return headline(self.category) if self.category else "Scam detected"


def score_text(text: str, multiplier: Callable[[str], float] | None = None) -> tuple[int, list[str], list[str]]:
    """Sum rule weights (each rule counts once, scaled by its learned reliability) plus a breadth bonus."""
    text = normalize(text)
    total, matches, labels, cats = 0, [], [], set()
    for cat, weight, rx, label in RULES:
        if rx.search(text):
            m = multiplier(label) if multiplier else 1.0
            w = round(weight * m)
            total += w
            cats.add(cat)
            labels.append(label)
            matches.append(f"{label} (+{w})" if m == 1.0 else f"{label} (+{w}, learned x{m:.1f})")
    # Scams usually combine several tactics (e.g. giveaway + urgency + Telegram).
    if len(cats) >= 3:
        total += 15
        matches.append("3+ scam categories (+15)")
    elif len(cats) == 2:
        total += 5
        matches.append("2 scam categories (+5)")
    return total, matches, labels


def decide(text: str, known_hit: str | None, hashes: list[str], threshold: int,
           ml_prob: float | None = None, ml_max: int = 40,
           findings: list[tuple[str, int]] | None = None,
           multiplier: Callable[[str], float] | None = None) -> Decision:
    """Known scam image match, or image-text rules + file/memory findings + learned model >= threshold."""
    if known_hit:
        return Decision(True, 100, f"image matches known scam ({known_hit})", [], hashes, True, text, 0,
                        category="Known image", signals=["Matches a known scam image"])
    rule_score, matches, labels = score_text(text, multiplier)
    # (points, category, short reason) for every contributor, to pick the headline and order the signals.
    parts = []
    for label, m in zip(labels, matches):
        pts = int(m.rsplit("(+", 1)[1].split(")")[0].split(",")[0])
        cat = "Nitro" if "Nitro" in label else CATEGORY_NAMES.get(_RULE_CATEGORY.get(label, ""), "Scam")
        parts.append((pts, cat, label.split(" (")[0]))
    for label, pts in findings or []:
        rule_score += pts
        matches.append(f"{label} (+{pts})")
        short = label.split(" (")[0].split(" ->")[0]
        parts.append((pts, finding_category(label), short))
    score = rule_score
    parts.sort(key=lambda p: -p[0])
    if ml_prob is not None:
        # Only pushes towards scam; below 70% (unsure) adds nothing, 100% adds ml_max.
        pts = round(ml_max * max(0.0, ml_prob - 0.7) / 0.3)
        if pts:
            score += pts
            matches.append(f"learned model {ml_prob:.0%} scam (+{pts})")
            # A supporting signal, never the headline (it can't say *what kind* of scam it is).
            parts.append((pts, "Learned pattern", "Resembles past scams"))
    category = parts[0][1] if parts else ""
    signals = list(dict.fromkeys(p[2][0].upper() + p[2][1:] for p in parts))
    op = ">=" if score >= threshold else "<"
    return Decision(score >= threshold, score, f"score {score} {op} {threshold}", matches, hashes, False,
                    text, rule_score, labels, category, signals)
