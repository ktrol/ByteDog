import asyncio
import io
import logging
import os
import random
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from urllib.parse import urlparse

import aiohttp
import discord
from discord import app_commands
from dotenv import load_dotenv

from scambot import attachments, imaging
from scambot.decision import Decision, decide, score_text
from scambot.learner import HAM, SCAM, Learner
from scambot.memory import Memory

load_dotenv(override=True)  # the .env file wins over stale terminal environment variables
log = logging.getLogger("scambot")
logging.basicConfig(level=logging.INFO)
# Also keep ByteDog's own log in a file (bytedog.log, next to bot.py) for troubleshooting.
_file_log = logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bytedog.log"),
                                encoding="utf-8")
_file_log.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_file_log)

TOKEN = os.environ["DISCORD_TOKEN"]
THRESHOLD = int(os.getenv("SCORE_THRESHOLD", 50))
HASH_DIST = int(os.getenv("HASH_MAX_DISTANCE", 6))
AUTO_LEARN = os.getenv("AUTO_LEARN", "true").lower() == "true"
ML_MAX_POINTS = int(os.getenv("ML_MAX_POINTS", 40))
HAM_SAMPLE_RATE = float(os.getenv("HAM_SAMPLE_RATE", 0.02))
ACTIONS = {a.strip() for a in os.getenv("ACTIONS", "delete,log").split(",")}
TIMEOUT_MIN = int(os.getenv("TIMEOUT_MINUTES", 60))
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", 0))
JAIL_ROLE_ID = int(os.getenv("JAIL_ROLE_ID", 0))
REPORT_EMOJI = os.getenv("REPORT_EMOJI", "\N{TRIANGULAR FLAG ON POST}")
REPORT_THRESHOLD = int(os.getenv("REPORT_THRESHOLD", 3))
LEARN_FROM_BANS = os.getenv("LEARN_FROM_BANS", "true").lower() == "true"
MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_IMAGES = 6  # per message
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".avif", ".svg")
VIDEO_EXT = (".mp4", ".webm", ".mov", ".m4v")

intents = discord.Intents.default()
intents.message_content = True
intents.members = True


class ScamBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.store = imaging.HashStore()
        self.learner = Learner(self.store.db)
        self.memory = Memory(self.store.db)
        self.reported: set[int] = set()  # message ids already sent for community review
        self.http_session: aiohttp.ClientSession | None = None

    async def setup_hook(self):
        # Some media hosts refuse requests without a normal browser User-Agent.
        self.http_session = aiohttp.ClientSession(headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/126.0 Safari/537.36 ByteDog/1.0"})
        self.add_dynamic_items(FeedbackButton)  # buttons keep working after restarts
        await self.tree.sync()

    async def close(self):
        if self.http_session:
            await self.http_session.close()
        await super().close()


# ---------------------------------------------------------------- extraction
def image_attachments(message: discord.Message) -> list[discord.Attachment]:
    """Attached pictures, GIFs and short videos."""
    def visual(a: discord.Attachment) -> bool:
        ct, name = a.content_type or "", a.filename.lower()
        return ct.startswith(("image/", "video/")) or name.endswith(IMAGE_EXT + VIDEO_EXT)
    return [a for a in message.attachments if visual(a)][:MAX_IMAGES]


def image_sources(message: discord.Message) -> list[list[str]]:
    """Media shown in embeds: pasted image links, and GIF-picker GIFs (Tenor/Giphy send these as MP4 videos).
    Each entry is a list of URLs to try in order: if one can't be downloaded or opened, the next is used."""
    groups: list[list[str]] = []
    for e in message.embeds:
        if e.type == "gifv" and e.video and e.video.url:
            # The whole animation first (direct, then via Discord's proxy), the still preview as a last resort.
            urls = [e.video.url, e.video.proxy_url]
            if e.thumbnail:
                urls += [e.thumbnail.proxy_url, e.thumbnail.url]
            groups.append([u for u in dict.fromkeys(urls) if u])
            continue
        for media in (e.image, e.thumbnail):
            if media and media.url:
                groups.append([u for u in dict.fromkeys([media.proxy_url, media.url]) if u])
        if e.type == "image" and e.url:
            groups.append([e.url])
    seen, out = set(), []
    for g in groups:
        if g[0] not in seen:
            seen.add(g[0])
            out.append(g)
    return out[:MAX_IMAGES]


def has_scannable(message: discord.Message) -> bool:
    return bool(message.attachments or image_sources(message))


async def read_attachment(a: discord.Attachment) -> bytes | None:
    if a.size > MAX_IMAGE_BYTES:
        log.info("Skipping %s: too large (%d bytes)", a.filename, a.size)
        return None
    try:
        return await a.read()
    except Exception as e:
        log.warning("Could not download %s: %s", a.filename, e)
        return None


async def download(url: str) -> bytes | None:
    session = bot.http_session
    if session is None:
        return None
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status != 200:
                log.warning("Download failed (HTTP %s): %s", r.status, url[:150])
                return None
            if int(r.headers.get("Content-Length", 0)) > MAX_IMAGE_BYTES:
                log.info("Skipping %s: too large", url[:150])
                return None
            # Read the whole body. (A single content.read(n) only returns what has arrived so far, which cut
            # GIFs off after the first few KB.)
            chunks, total = [], 0
            async for chunk in r.content.iter_chunked(64 * 1024):
                total += len(chunk)
                if total > MAX_IMAGE_BYTES:
                    log.info("Skipping %s: too large", url[:150])
                    return None
                chunks.append(chunk)
            return b"".join(chunks)
    except Exception as e:
        log.warning("Download failed (%s): %s", type(e).__name__, url[:150])
        return None


@dataclass
class Scan:
    text: str = ""  # everything read from the images (OCR + QR contents), pieced together
    hashes: list[str] = field(default_factory=list)
    findings: list[tuple[str, int]] = field(default_factory=list)  # file-level red flags
    known_hit: str | None = None
    images: int = 0
    preview: bytes | None = None  # clean copy of the first image, to show the user what was removed


async def scan(message: discord.Message, stop_on_known: bool = True) -> Scan:
    s = Scan()
    loop = asyncio.get_running_loop()
    for a in message.attachments:
        s.findings += attachments.check_filename(a.filename)
    parts: list[str] = []
    groups = image_sources(message)
    log.info("Media found: %d attachment(s), embeds %s -> %d link group(s) %s",
             len(image_attachments(message)), [e.type for e in message.embeds], len(groups),
             [[urlparse(u).netloc for u in g] for g in groups])
    sources = [[partial(read_attachment, a)] for a in image_attachments(message)]
    sources += [[partial(download, u) for u in group] for group in groups]
    for candidates in sources:
        # Try each URL for this piece of media until one downloads and opens.
        data, fr = None, None
        for fetch in candidates:
            got = await fetch()
            if not got:
                continue
            data = got
            fr = await loop.run_in_executor(None, imaging.load_frames, got)
            if fr is not None:
                log.info("Opened media: %d bytes, %d frame(s) to read", len(got), len(fr.frames))
                break
            log.warning("Could not open media (%d bytes, starts with %r)", len(got), got[:12])
        if data is None:
            continue
        s.findings += attachments.check_image_bytes(data)
        # Stage 1: image hashing (every distinct GIF frame).
        if fr is None:
            continue
        s.images += 1
        s.hashes += fr.hashes
        hit_at = next((i for i, h in enumerate(fr.hashes) if bot.store.match(h, HASH_DIST)), None)
        if hit_at is not None and stop_on_known:
            s.known_hit = bot.store.match(fr.hashes[hit_at], HASH_DIST)
            if s.preview is None:  # show the frame that matched
                s.preview = await loop.run_in_executor(None, imaging.preview_png, fr.frames[hit_at])
            break
        # Stage 2: OCR every scene + decode QR codes, pieced together in reading order.
        # For long GIFs/videos: stop reading once the text alone already reaches the threshold (the final
        # score only adds to it, so the verdict can't change by reading the remaining frames).
        certain = (lambda t: score_text(t, bot.memory.rule_multiplier)[0] >= THRESHOLD) if stop_on_known else None
        text, qrs, best = await loop.run_in_executor(None, partial(imaging.read_frames, fr.frames, certain))
        if s.preview is None:  # show the frame with the most text (the scam, not the meme around it)
            s.preview = await loop.run_in_executor(None, imaging.preview_png, fr.frames[best])
        if text:
            parts.append(text)
        for q in qrs:
            parts.append(q)
            s.findings.append((f"QR code in image -> {q[:80]}", 15))
    s.text = "\n".join(parts)
    s.findings = list(dict.fromkeys(s.findings))
    return s


async def analyze(message: discord.Message) -> tuple[Decision, Scan]:
    s = await scan(message)
    guild_id = message.guild.id if message.guild else 0
    findings = s.findings + bot.memory.check(s.text)  # known scam links / wording templates
    findings += bot.memory.wave(guild_id, message.author.id, message.channel.id, s.hashes, HASH_DIST)
    # Stage 3: decision engine (image-text rules with learned weights + findings + learned model).
    d = decide(s.text, s.known_hit, s.hashes, THRESHOLD,
               bot.learner.prob_scam(s.text) if s.text else None, ML_MAX_POINTS, findings,
               bot.memory.rule_multiplier)
    return d, s


def teach(text: str, hashes: list[str], rule_labels: list[str], label: int, source: str, note: str,
          detection_id: int | None = None, count_rules: bool = True):
    """One place that updates every kind of memory: image hashes, text model, links, templates, rule weights."""
    if label == SCAM:
        for h in hashes:
            bot.store.add(h, note)
        bot.memory.learn_scam(text, rule_labels, note, count_rules)
    else:
        for h in hashes:
            bot.store.remove_near(h, 0 if detection_id else HASH_DIST)
        bot.memory.learn_ham(text, rule_labels)
    if detection_id:
        bot.learner.relabel_detection(detection_id, label, source)
    elif text:
        bot.learner.add(text, label, source)


class FeedbackButton(discord.ui.DynamicItem[discord.ui.Button], template=r"fb:(?P<action>scam|ham):(?P<id>\d+)"):
    """Buttons on each log alert. Moderator clicks are the main way the bot learns."""

    def __init__(self, action: str, detection_id: int):
        scam_ = action == "scam"
        super().__init__(discord.ui.Button(
            label="Confirm scam" if scam_ else "Not a scam",
            style=discord.ButtonStyle.danger if scam_ else discord.ButtonStyle.success,
            custom_id=f"fb:{action}:{detection_id}"))
        self.action, self.detection_id = action, detection_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(match["action"], int(match["id"]))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.permissions.manage_messages:
            return True
        await interaction.response.send_message("Only moderators can do this.", ephemeral=True)
        return False

    async def callback(self, interaction: discord.Interaction):
        det = bot.learner.get_detection(self.detection_id)
        if not det:
            await interaction.response.send_message("Detection not found.", ephemeral=True)
            return
        if self.action == "scam":
            teach(det["text"], det["hashes"], det["rule_labels"], SCAM, "mod", f"confirmed by {interaction.user}",
                  self.detection_id)
            extra = ""
            # Community reports leave the message up until a moderator confirms it.
            ch = bot.get_channel(det["channel_id"] or 0)
            if det["message_id"] and isinstance(ch, discord.abc.Messageable):
                try:
                    await (await ch.fetch_message(det["message_id"])).delete()
                    extra = " Message deleted."
                except (discord.NotFound, discord.Forbidden):
                    pass
            verdict = f"Confirmed as scam by {interaction.user.mention}. The bot learned from it.{extra}"
        else:
            teach(det["text"], det["hashes"], det["rule_labels"], HAM, "mod", f"cleared by {interaction.user}",
                  self.detection_id)
            undo = ""
            if interaction.guild and (m := interaction.guild.get_member(det["user_id"])) and m.is_timed_out():
                try:
                    await m.timeout(None, reason="False positive")
                    undo = " Timeout removed."
                except discord.Forbidden:
                    pass
            verdict = f"Marked as **not a scam** by {interaction.user.mention}. The bot learned from it.{undo}"
        await interaction.response.edit_message(content=verdict, view=None)


def user_reasons(d: Decision) -> list[str]:
    """Plain-language reasons for the user, without scores (no need to teach scammers the thresholds)."""
    return d.signals[:3] or ["Matches patterns commonly used in scams"]


def reason_block(d: Decision) -> str:
    """Short verdict in a code block, plus a one-line list of the strongest signals."""
    extra = len(d.signals) - 3
    signals = ", ".join(user_reasons(d)) + (f" +{extra} more" if extra > 0 else "")
    return f"```{d.headline}```{signals}"


def warning_embed(message: discord.Message, d: Decision, detection_id: int, preview_name: str | None) -> discord.Embed:
    guild_name = message.guild.name if message.guild else "the server"
    emb = discord.Embed(
        title="Your message was removed",
        color=discord.Color.orange(),
        description=(f"A message you posted in **{guild_name}** (<#{message.channel.id}>) was removed by our "
                     "automated security system because the attached image or file appears to contain a scam "
                     "or malicious content."),
    )
    # Show the user what they sent: their caption, file names, the text found in the image, and the image itself.
    emb.add_field(name="Your message", value=(message.content or "*(no text, attachment only)*")[:1000],
                  inline=False)
    if message.attachments:
        emb.add_field(name="Attachments", value=", ".join(f"`{a.filename}`" for a in message.attachments)[:1000],
                      inline=False)
    if d.text.strip():
        snippet = d.text.strip().replace("\n", " ")
        emb.add_field(name="Text found in your image",
                      value=f">>> {snippet[:400]}{'...' if len(snippet) > 400 else ''}", inline=False)
    if preview_name:
        emb.set_image(url=f"attachment://{preview_name}")
    emb.add_field(name="Why it was removed", value=reason_block(d)[:1000], inline=False)
    action = "Your message was deleted and the moderation team has been notified."
    if "timeout" in ACTIONS:
        action += f" You have been timed out for **{TIMEOUT_MIN} minutes**."
    emb.add_field(name="Action taken", value=action, inline=False)
    emb.add_field(
        name="Did you send this?",
        value=("If you did not post this, your account may be compromised. Please change your Discord password, "
               "enable two-factor authentication, and review your authorized apps under "
               "*User Settings > Authorized Apps*."),
        inline=False)
    emb.add_field(
        name="Think this was a mistake?",
        value=f"Contact a moderator of **{guild_name}** and mention reference **#{detection_id}**.",
        inline=False)
    emb.set_footer(text=f"{guild_name} - Automated Security")
    emb.timestamp = discord.utils.utcnow()
    return emb


def log_channel() -> discord.abc.Messageable | None:
    if not LOG_CHANNEL_ID:
        return None
    ch = bot.get_channel(LOG_CHANNEL_ID)
    if not isinstance(ch, discord.abc.Messageable):
        log.warning("Log channel %s not found: the bot can't see it. Give the bot View Channel there.", LOG_CHANNEL_ID)
        return None
    return ch


def fmt_duration(minutes: int) -> str:
    """60 -> "1 hour (1h)", 1440 -> "1 day (1d)", 30 -> "30 minutes (30m)"."""
    for size, word, short in ((1440, "day", "d"), (60, "hour", "h"), (1, "minute", "m")):
        if minutes % size == 0:
            n = minutes // size
            return f"{n} {word}{'s' if n != 1 else ''} ({n}{short})"
    return f"{minutes} minutes"


async def send_review(message: discord.Message, d: Decision, detection_id: int, intro: str, sanction: str,
                      notes: list[str], color: discord.Color, preview: bytes | None = None):
    """Compact mod-log alert in the style of common antiscam bots: who, what was done, a one-line verdict,
    and the image itself shown full-size so moderators can judge it at a glance."""
    ch = log_channel()
    if ch is None:
        return
    author = message.author
    lines = [intro, f"{author.mention} ({author.name})", f"\N{SQUARED ID} `{author.id}`",
             f"{sanction}", f"```{d.headline if d.score else 'Needs review'}```"]
    if d.signals:
        extra = len(d.signals) - 3
        lines.append(f"\N{LEFT-POINTING MAGNIFYING GLASS} Flagged for: {', '.join(d.signals[:3])}"
                     + (f" (+{extra} more)" if extra > 0 else ""))
    lines += notes
    mod = bot.user.mention if bot.user else "ByteDog"
    lines.append(f"\N{SQUARED ID} `#{detection_id}` • Score {d.score} • Mod : {mod}")
    emb = discord.Embed(color=color, description="\n".join(lines)[:4000])
    # The original attachment URL dies once the message is deleted, so show our own clean copy, full size.
    file = discord.File(io.BytesIO(preview), filename="flagged.png") if preview else discord.utils.MISSING
    if preview:
        emb.set_image(url="attachment://flagged.png")
    emb.timestamp = discord.utils.utcnow()
    view = discord.ui.View(timeout=None)
    view.add_item(FeedbackButton("scam", detection_id))
    view.add_item(FeedbackButton("ham", detection_id))
    await ch.send(embed=emb, view=view, file=file)


async def act(message: discord.Message, d: Decision, detection_id: int, preview: bytes | None = None):
    member, guild = message.author, message.guild
    if not isinstance(member, discord.Member) or guild is None:
        return
    notes: list[str] = []
    sanctions: list[str] = []
    deleted = False
    if "delete" in ACTIONS:
        try:
            await message.delete()
            deleted = True
        except discord.NotFound:
            deleted = True  # already removed (e.g. by a moderator)
        except discord.Forbidden:
            notes.append("\N{WARNING SIGN} Could not delete: missing Manage Messages permission.")
    if "timeout" in ACTIONS:
        try:
            await member.timeout(timedelta(minutes=TIMEOUT_MIN), reason=f"ByteDog: {d.headline}")
            sanctions.append(f"\N{SPEAKER WITH CANCELLATION STROKE} Timeout for {fmt_duration(TIMEOUT_MIN)}")
        except discord.Forbidden:
            notes.append("\N{INFORMATION SOURCE} Not timed out: their role is above ByteDog's, or they are an admin.")
    if "jail" in ACTIONS and JAIL_ROLE_ID:
        role = guild.get_role(JAIL_ROLE_ID)
        try:
            if role:
                await member.add_roles(role, reason=f"ByteDog: {d.headline}")
                sanctions.append(f"\N{LOCK} Jailed ({role.mention})")
        except discord.Forbidden:
            notes.append("\N{INFORMATION SOURCE} Not jailed: missing Manage Roles or role too high.")
    if "warn" in ACTIONS:
        try:
            if preview:
                name = "removed_image.png"
                await member.send(embed=warning_embed(message, d, detection_id, name),
                                  file=discord.File(io.BytesIO(preview), filename=name))
            else:
                await member.send(embed=warning_embed(message, d, detection_id, None))
            notes.append("\N{ENVELOPE} User notified by DM.")
        except discord.Forbidden:
            notes.append("\N{ENVELOPE} DMs closed: warned in the channel instead.")
            if isinstance(message.channel, discord.abc.Messageable):
                await message.channel.send(
                    f"{member.mention}, your attachment was removed by our automated security system because it "
                    "appears to contain scam or malicious content. Please contact a moderator if you believe "
                    "this was a mistake.", delete_after=30)
    else:
        notes.append("\N{INFORMATION SOURCE} Silent sanction, the user was not notified.")
    if "log" in ACTIONS:
        verb = "blocked" if deleted else "flagged"
        intro = f"\N{SHIELD} ByteDog {verb} a scam from {member.mention} in <#{message.channel.id}>."
        if deleted:
            sanctions.insert(0, "\N{WASTEBASKET} Message deleted")
        sanction = (" • ".join(sanctions) or "\N{WARNING SIGN} No action taken") + " :"
        await send_review(message, d, detection_id, intro, sanction, notes, discord.Color.red(), preview)


bot = ScamBot()


@bot.event
async def on_ready():
    st = bot.learner.stats()
    log.info("Logged in as %s, %d known scam hashes, model trained on %d scam / %d normal examples",
             bot.user, len(bot.store.cache), st["scam"], st["normal"])


async def handle(message: discord.Message):
    if message.author.bot or not message.guild or not isinstance(message.author, discord.Member):
        return
    if message.author.guild_permissions.manage_messages:  # trust moderators
        return
    if not has_scannable(message):  # images and attachments only; plain text is ignored
        return
    log.info("Scanning message from %s: %d attachment(s)", message.author, len(message.attachments))
    d, s = await analyze(message)
    log.info("Scanned %d image(s), score %d, text read: %r", s.images, d.score, s.text[:120])
    # Remember recent posts: spots spam waves, and lets a later ban teach the bot.
    bot.memory.remember_post(message.guild.id, message.author.id, message.channel.id, s.hashes, s.text,
                             d.score if d.known_match else d.rule_score)
    if not d.is_scam:
        # Learn what normal images look like from a small random sample of clearly clean ones.
        if AUTO_LEARN and s.text and d.score == 0 and random.random() < HAM_SAMPLE_RATE:
            bot.learner.add(s.text, HAM, "sampled")
        return
    log.info("Scam from %s: %s %s", message.author, d.reason, d.matches)
    detection_id = bot.learner.record_detection(message.guild.id, message.author.id, d.text, d.hashes, d.score,
                                                d.rule_labels, message.channel.id, message.id)
    # Only learn on our own when very sure; borderline cases wait for a moderator click.
    # Rule reliability is only updated by humans, so the bot can't reinforce its own mistakes.
    if AUTO_LEARN and (d.known_match or d.rule_score >= 2 * THRESHOLD):
        teach(d.text, d.hashes, d.rule_labels, SCAM, "auto", f"auto: {d.reason}", detection_id, count_rules=False)
    try:
        await act(message, d, detection_id, s.preview)
    except discord.Forbidden as e:
        log.warning("Missing permissions: %s", e)
    except Exception:
        log.exception("Action failed")


@bot.event
async def on_message(message: discord.Message):
    try:
        await handle(message)
    except Exception:
        log.exception("Scan failed")


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    # Discord adds link-preview images a moment after the message is sent.
    if not image_sources(before) and image_sources(after):
        try:
            await handle(after)
        except Exception:
            log.exception("Scan failed")


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User | discord.Member):
    """A moderator banned someone: their recent suspicious images are learned as scams."""
    if not LEARN_FROM_BANS:
        return
    learned = 0
    for hashes, text, rule_score in bot.memory.recent_from(guild.id, user.id):
        # Only posts that already looked a bit suspicious, so a ban for other reasons doesn't teach memes as scams.
        if rule_score > 0:
            _, _, labels = score_text(text)
            teach(text, hashes, labels, SCAM, "ban", f"posted by banned user {user}", count_rules=False)
            learned += 1
    if learned:
        log.info("Learned %d image(s) from banned user %s", learned, user)
        ch = log_channel()
        if ch:
            await ch.send(f"Learned **{learned}** suspicious image(s) posted by banned user {user.mention} "
                          f"in the last hour.")


@bot.event
async def on_raw_reaction_add(payload: discord.RawReactionActionEvent):
    """Community reports: once enough members react with the report emoji, moderators get a review alert."""
    if str(payload.emoji) != REPORT_EMOJI or not payload.guild_id or payload.message_id in bot.reported:
        return
    ch = bot.get_channel(payload.channel_id)
    if not isinstance(ch, discord.abc.Messageable):
        return
    try:
        message = await ch.fetch_message(payload.message_id)
    except (discord.NotFound, discord.Forbidden):
        return
    reaction = next((r for r in message.reactions if str(r.emoji) == REPORT_EMOJI), None)
    if reaction is None or reaction.count < REPORT_THRESHOLD or message.author.bot or not has_scannable(message):
        return
    bot.reported.add(message.id)
    try:
        d, s = await analyze(message)
        detection_id = bot.learner.record_detection(payload.guild_id, message.author.id, d.text, d.hashes, d.score,
                                                    d.rule_labels, message.channel.id, message.id)
        log.info("Community report on message %s (%d reports), score %d", message.id, reaction.count, d.score)
        if d.is_scam and isinstance(message.author, discord.Member) \
                and not message.author.guild_permissions.manage_messages:
            await act(message, d, detection_id, s.preview)  # the bot agrees: handle it like a normal detection
        else:
            await send_review(
                message, d, detection_id,
                f"{REPORT_EMOJI} {reaction.count} members reported an image from {message.author.mention} "
                f"in <#{message.channel.id}>.",
                "\N{HOURGLASS WITH FLOWING SAND} Waiting for a moderator :",
                [f"\N{INFORMATION SOURCE} Still up: [jump to message]({message.jump_url}). Confirming will delete it."],
                discord.Color.gold(), s.preview)
    except Exception:
        log.exception("Report handling failed")


# ------------------------------------------------- moderator teaching tools
@bot.tree.context_menu(name="Mark as scam")
@app_commands.default_permissions(manage_messages=True)
async def mark_scam(interaction: discord.Interaction, message: discord.Message):
    await interaction.response.defer(ephemeral=True)
    s = await scan(message, stop_on_known=False)
    if not s.images and not message.attachments:
        await interaction.followup.send("That message has no images or attachments to learn from.", ephemeral=True)
        return
    _, _, labels = score_text(s.text)
    teach(s.text, s.hashes, labels, SCAM, "mod", f"manual by {interaction.user}")
    await interaction.followup.send(
        f"Learned as a scam: {len(s.hashes)} image fingerprint(s)"
        f"{', its wording, links and rule matches' if s.text else ''} saved.", ephemeral=True)


@bot.tree.context_menu(name="Not a scam")
@app_commands.default_permissions(manage_messages=True)
async def not_scam(interaction: discord.Interaction, message: discord.Message):
    await interaction.response.defer(ephemeral=True)
    s = await scan(message, stop_on_known=False)
    before = len(bot.store.cache)
    _, _, labels = score_text(s.text)
    teach(s.text, s.hashes, labels, HAM, "mod", f"cleared by {interaction.user}")
    await interaction.followup.send(
        f"Learned as normal: {before - len(bot.store.cache)} matching scam fingerprint(s) removed"
        f"{', and its wording, links and rule matches marked as safe' if s.text else ''}.", ephemeral=True)


@bot.tree.command(name="scamstats", description="Show what the scam detector has learned")
@app_commands.default_permissions(manage_messages=True)
async def scamstats(interaction: discord.Interaction):
    st = bot.learner.stats()
    mem = bot.memory.stats()
    lines = [f"Known scam images: **{len(bot.store.cache)}**",
             f"Known scam links/sites: **{mem['links']}**",
             f"Known scam wording templates: **{mem['templates']}**",
             f"Model examples: **{st['scam']}** scam / **{st['normal']}** normal "
             f"({'active' if st['ready'] else 'not active yet'})"]
    lines += [f"- {k}: {v}" for k, v in sorted(st["by_source"].items())]
    if mem["tuned_rules"]:
        lines.append("Rules re-weighted from feedback:")
        lines += [f"- {k}: x{v}" for k, v in sorted(mem["tuned_rules"].items(), key=lambda kv: kv[1])][:15]
    await interaction.response.send_message("\n".join(lines)[:1900], ephemeral=True)


bot.run(TOKEN)
