"""Scam phrase rules. Each rule is (category, weight, regex, label).

Text coming from OCR is noisy, so patterns tolerate missing punctuation and use
bounded gaps (.{0,N}) instead of exact wording. Weights are summed by the
decision engine; a single weak phrase never trips the default threshold (50).
"""
import re
import unicodedata

_R = [
    # --- Crypto giveaways / wallet drainers -------------------------------
    ("crypto", 45, r"(send|deposit)\W{0,3}\d[\d.,]*\s?(btc|eth|usdt|sol|bnb).{0,60}(receive|get|back)", "send X crypto, receive more"),
    ("crypto", 45, r"(double|triple|multiply)\s(your\s)?(crypto|bitcoin|btc|eth|money|coins?)", "double your crypto"),
    ("crypto", 30, r"(elon|musk|vitalik|cz\b|binance).{0,40}giveaway|giveaway.{0,40}(elon|musk|vitalik)", "celebrity giveaway"),
    ("crypto", 25, r"giveaway.{0,50}(btc|eth|usdt|bitcoin|ethereum|crypto)", "crypto giveaway"),
    ("crypto", 30, r"connect\s(your\s)?wallet", "connect wallet"),
    ("crypto", 40, r"(seed|recovery|secret)\sphrase|private\skey|12.word", "seed phrase / private key"),
    ("crypto", 25, r"claim\s(your\s)?(free\s)?(reward|prize|airdrop|bonus|tokens?)", "claim reward/airdrop"),
    ("crypto", 15, r"\bairdrop\b", "airdrop"),
    ("crypto", 15, r"promo\s?code.{0,30}(bonus|deposit|free)|use\scode\s\w+.{0,30}(bonus|deposit)", "promo code bonus"),
    ("crypto", 20, r"(free|instant)\s(btc|bitcoin|eth|ethereum|usdt)", "free crypto"),
    ("crypto", 25, r"(casino|stake|roobet).{0,40}(promo|bonus|code|free)|(promo|bonus|code).{0,40}(casino|stake\.com)", "casino promo"),
    ("crypto", 35, r"giving\saway\s[$£€]?\s?\d[\d,.]*\s?(k|usd|usdt|btc|eth)?.{0,40}(everyone|every\sone|first\s\d+|people|users|who\s(registers|signs|joins))", "giving away $X to everyone"),
    ("crypto", 25, r"withdraw\s(the\s|your\s)?(bonus|winnings|reward|balance)\s(immediately|instantly|right\saway|now)", "withdraw bonus immediately"),
    ("crypto", 25, r"(enter|use|apply|activate)\s(the\s|my\s)?(special\s|exclusive\s|secret\s)?(promo|bonus|referral)\s?code", "enter the special promo code"),

    # --- Fake jobs / task scams -------------------------------------------
    ("job", 30, r"(earn|make)\W{0,3}[$£€]?\s?\d[\d,]*.{0,25}(per|a|every|each)\s(day|hour|week|daily)", "earn $X per day"),
    ("job", 25, r"(hiring|recruiting|vacanc|job\soffer|part.time).{0,60}(dm|message|text|contact|telegram|whatsapp)", "hiring, contact via DM/messenger"),
    ("job", 15, r"no\sexperience\s(needed|required|necessary)", "no experience needed"),
    ("job", 15, r"(work|earn)\s(from\shome|online|remotely).{0,40}(\$|\d)", "work from home"),
    ("job", 25, r"(like|rate|review|watch|click).{0,30}(videos?|products?|apps?|ads?).{0,40}(earn|paid|get\s\$)", "paid micro-tasks"),
    ("job", 15, r"daily\stasks?|task\splatform|complete\s(the\s)?tasks?", "task platform"),
    ("job", 20, r"(commission|salary).{0,30}(paid|withdraw).{0,20}(daily|instantly|immediately)", "instant payout"),

    # --- Investment / recovery / trading ----------------------------------
    ("invest", 40, r"guaranteed\s(profit|returns?|income|earnings?)", "guaranteed profit"),
    ("invest", 35, r"\d{2,4}\s?%\s(profit|returns?|roi).{0,25}(daily|weekly|in\s\d|within|hours?)", "extreme % returns"),
    ("invest", 30, r"(i|we)\s(just\s)?(made|earned|profited|withdrew|turned).{0,25}[$£€]\s?\d[\d,]*.{0,25}(in|within|from|after|today|week|days?)", "I made $X in Y"),
    ("invest", 20, r"ask\sme\show|dm\sme\s(to\slearn|for\s(details|info|more)|now|today)|message\sme\sto\s(learn|start|invest)", "ask me how / DM me"),
    ("invest", 40, r"recover.{0,15}(lost|stolen|scammed)\s(funds|crypto|bitcoin|money|assets)", "fund recovery service"),
    ("invest", 15, r"trading\ssignals?|forex|binary\soptions?|copy\strad(e|ing)", "trading/forex"),
    ("invest", 20, r"(withdrawal|payout)\s(proof|successful|received)|proof\sof\s(payment|withdrawal)", "withdrawal proof"),
    ("invest", 25, r"(crypto|investment|trading)\s(mentor|expert|manager|broker|advisor)", "mentor/broker"),
    ("invest", 15, r"(financial|passive)\s(freedom|income)", "financial freedom"),

    # --- Fake Nitro / gifts / skins ---------------------------------------
    ("gift", 40, r"free\s(discord\s)?nitro|nitro\s(for\sfree|giveaway)", "free Nitro"),
    ("gift", 35, r"(discord\s)?nitro.{0,30}(gift|claim|redeem|gifted)", "Nitro gift claim"),
    ("gift", 25, r"(gifted|sent)\syou.{0,25}(nitro|gift|steam|skin)", "gifted you ..."),
    ("gift", 20, r"steam\s(gift|wallet).{0,30}(card|code|claim)", "Steam gift"),
    ("gift", 35, r"free\s(cs\s?go|cs2|csgo)?\s?(skins?|knife|case)", "free skins"),
    ("gift", 25, r"(claim|redeem).{0,20}(gift|reward|prize)", "claim/redeem gift"),

    # --- Phishing / urgency / verification --------------------------------
    ("phish", 30, r"verify\s(your\s)?(account|identity|wallet|age)", "verify your account"),
    ("phish", 35, r"(account|profile).{0,25}(will\sbe|has\sbeen|is)\s(suspended|disabled|banned|terminated|deleted|locked)", "account will be suspended"),
    ("phish", 25, r"scan\s(the\s)?(this\s)?qr(\scode)?", "scan QR code"),
    ("phish", 25, r"suspicious\s(activity|login|sign.?in)|unusual\s(activity|login)", "suspicious activity"),
    ("phish", 25, r"log\s?in\sto\s(claim|verify|continue|confirm)|sign\sin\sto\s(claim|verify|continue)", "login to claim/verify"),
    ("phish", 20, r"discord\s(staff|moderator|security|trust\s(and|&)\ssafety)\s?(team)?", "impersonating Discord staff"),
    ("phish", 30, r"(you|you've|you\shave)\s(have\s)?(won|been\sselected|been\schosen)", "you have won"),
    ("phish", 15, r"click\s(the\s)?(link|here|below)|link\sin\s(bio|description)", "click the link"),
    ("phish", 10, r"(urgent|immediately|act\snow|expires?\s(in|soon)|within\s24\shours|limited\stime)", "urgency"),
    ("phish", 10, r"congratulations|congrats", "congratulations"),

    # --- Fake fines / billing / delivery (brand impersonation) ------------
    ("billing", 35, r"(you\shave\sbeen|you\swere|you've\sbeen)\s(fined|charged|billed|penalized)", "you have been fined/charged"),
    ("billing", 25, r"(pay|settle)\s(this|the|your|an?)\s(outstanding\s)?(fine|fee|penalty|balance|toll|invoice)", "pay the fine/fee"),
    ("billing", 30, r"(fail(ed|ing|ure)\sto\s(return|pay|deliver)|unpaid\s(toll|invoice|balance|fee))", "failed to return/pay"),
    ("billing", 25, r"(package|parcel|shipment|delivery).{0,40}(on\shold|failed|could\snot\sbe\sdelivered|undeliverable|redeliver|customs\sfee)", "delivery problem"),
    ("billing", 25, r"(refund|waiver?|waive|compensation).{0,30}(apply|claim|click|log\s?in|below|link)|apply\sfor\sa\s(refund|waiver?|waive)", "apply for refund/waiver"),
    ("billing", 15, r"order\s(no\.?|number|#|id)\s?[:#]?\s?#?\d{5,}", "order number"),
    ("billing", 15, r"(amazon|paypal|usps|fedex|dhl|ups|netflix|apple|ebay|bank|e-?zpass|irs)\b.{0,80}(fine|fee|suspend|verify|log\s?in|payment|refund|charged)", "brand + payment/account action"),
    ("billing", 45, r"amaz[o0]n\.(con|co(?!m)|cm|om)\b|amaz0n|arnazon|paypa[l1]\.(?!com)|pa[yv]pai", "lookalike brand domain"),
    ("phish", 20, r"log\s?in\s(below|here|now|to\spay|to\savoid)|sign\sin\sbelow", "log in below"),
    ("phish", 15, r"within\s\d{1,3}\s(hours?|hrs?|days?)|in\sthe\snext\s\d{1,3}\s(hours?|days?)", "deadline"),
    ("phish", 10, r"\b(attention|final\snotice|action\srequired|important\snotice)\b", "alarm header"),

    # --- Discord account takeover ("accidentally reported", fake staff) ---
    ("account", 40, r"(accidentally|mistakenly|by\saccident)\s(reported|flagged|banned|mass.reported)", "accidentally reported you"),
    ("account", 30, r"(contact|message|add|dm)\s(the\s|this\s|our\s)?(discord\s)?(support|staff|admin|agent|moderator)s?\s?(team|agent)?.{0,40}(before|or\syou|to\savoid|immediately|ban|disabled|terminated)", "contact support or be banned"),
    ("account", 25, r"(your\saccount|you)\s(is|are|has\sbeen|have\sbeen|will\sbe)\s(flagged|mass.reported|under\sreview|being\sinvestigated)", "account flagged/under review"),
    ("account", 30, r"hype\s?squad\s(event|application|recruit|apply)|selected\s(as|for|to\sbe)\s(a\s)?(moderator|tester|hypesquad|staff|partner)", "fake HypeSquad/mod selection"),
    ("account", 40, r"(send|give|share|tell)\s(me\s)?(your\s)?(token|password|2fa|backup\scodes?|login\scode|verification\scode)", "asks for token/password/code"),
    ("account", 20, r"(captcha|verification)\s?(bot)?.{0,30}(scan|qr|authorize)", "fake captcha/verify"),
    ("account", 60, r"discord(app)?\.com/ra/", "QR code is a Discord login code (account takeover)"),

    # --- Malware lures ("try my game") -------------------------------------
    ("malware", 20, r"(try|test|play)\s(out\s)?my\s(new\s)?(game|app|program|mod|launcher|cheat)", "try my game"),
    ("malware", 30, r"\.(exe|scr|bat|msi|apk)\b|(password|pass)\b.{0,25}\b(zip|rar|7z|exe|file)\b|\b(zip|rar|7z)\b.{0,25}\bpassword\b|(run|open|install)\s(the\s|this\s|my\s)?(exe|setup|launcher|installer)", "suspicious download"),
    ("malware", 10, r"beta\stest(er|ing)?|game\stester", "beta tester"),

    # --- Giveaways and free stuff ------------------------------------------
    ("gift", 35, r"mr\.?\s?beast.{0,60}(giveaway|gift|claim|winner|free|\$)", "MrBeast giveaway"),
    ("gift", 30, r"free\s(robux|v-?bucks|spotify(\spremium)?|netflix|youtube\spremium|gift\s?cards?)", "free Robux/V-Bucks/etc"),
    ("gift", 25, r"\$\s?50\s(steam|gift)|steam.{0,20}\$\s?\d{2,3}.{0,20}(gift|free)", "free $50 Steam"),

    # --- Adult lures / sextortion ------------------------------------------
    ("adult", 35, r"(teen|underage|leaked?|leaks)\s(nudes?|pics?|videos?|content|nsfw)|(nudes?|nsfw|onlyfans|e-?girl)\s(leaks?|for\sfree|free)", "leaked NSFW lure"),
    ("adult", 20, r"18\+\s?(server|content|leaks|videos)|hot\s(singles|girls)\s(in|near)", "adult lure"),
    ("extortion", 45, r"i\shave\s(your\s)?((compromising|private|intimate|explicit|naked|nude)\s(photos?|pictures?|pics|videos?|content)|nudes)", "claims to have compromising photos"),
    ("extortion", 30, r"(send|show|share|post|leak)\s(them|it|this|these)?\s?(to\s)?(all\s)?(of\s)?your\s(friends|family|followers|contacts|parents)", "send to your friends/family"),
    ("extortion", 40, r"(pay|send)\s.{0,30}(or|otherwise)\s(i('ll|\swill)\s)?(send|share|post|leak|expose|release)", "pay or I leak"),
    ("extortion", 30, r"(your\s)?(friends|family|followers|parents|school)\s(will\s)?(see|know)\s(this|everything|it)|ruin\syour\s(life|reputation)", "threat to expose"),

    # --- Pig butchering / money scams --------------------------------------
    ("invest", 25, r"(withdraw|withdrawal).{0,40}(tax|fee|kyc|unlock|deposit\sfirst)", "withdrawal fee/tax"),
    ("invest", 20, r"keep\s(this|it)\s(between\sus|secret|private)|don'?t\stell\sanyone", "keep it secret"),
    ("invest", 15, r"sorry,?\s(wrong\snumber|i\sthink\si\shave\sthe\swrong)|wrong\s(number|person)\?", "wrong-number opener"),
    ("invest", 30, r"(cash\s?app|zelle|venmo|paypal)\s(flip|flipping)|money\sflip|flip\syour\s(money|\$)", "money flipping"),
    ("crypto", 20, r"(ai|bot|automated)\s(trading|arbitrage)\s(bot|platform|system)|crypto\sarbitrage", "AI trading bot"),
    ("money", 25, r"gift\s?cards?.{0,40}(codes?|pay|send|photo|picture|scratch)|(pay|buy).{0,20}gift\s?cards?", "gift card payment"),
    ("money", 25, r"(bank|card|account)\s(has\sbeen\s|is\s|was\s)?(frozen|locked|suspended|blocked|compromised)", "bank account locked"),
    ("money", 20, r"(loan|grant)\s(has\sbeen\s)?(approved|pre-?approved)|you\squalify\sfor\sa\s(loan|grant)", "loan/grant approved"),
    ("money", 25, r"(irs|hmrc|tax\soffice).{0,50}(refund|owe|arrest|warrant|lawsuit)|tax\srefund.{0,30}(claim|click|pending)", "tax refund/IRS"),
    ("job", 25, r"(training|registration|onboarding|equipment)\s(fee|deposit|cost)|will\sbe\sreimbursed", "pay for training/equipment"),

    # --- Tech support ------------------------------------------------------
    ("techsupport", 30, r"(computer|device|pc|phone|iphone)\s(is|has\sbeen|was)\s(infected|hacked|compromised|locked)|virus\s(detected|found)", "device infected"),
    ("techsupport", 30, r"(call|contact)\s(us\s|support\s)?(now\s|immediately\s)?(at|on)?\s?\+?1?[\s.-]?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}", "call this number"),
    ("techsupport", 25, r"(microsoft|windows|apple|icloud)\s(support|security|defender)\s(team|alert|warning)|apple\sid\s(is|has\sbeen)\s(locked|disabled)", "fake tech support"),

    # --- Move off-platform -------------------------------------------------
    ("contact", 20, r"\bt\.me/|\bwa\.me/|telegram\.me/", "Telegram/WhatsApp link"),
    ("contact", 10, r"(telegram|whatsapp|signal)\s?[:@]?\s?[@+]?\w{3,}", "Telegram/WhatsApp contact"),

    # --- URL heuristics ----------------------------------------------------
    ("url", 45, r"discord[-.]?(nitro|gifts?|app|promo|airdrop|give|free|claim)\w*\.(com|gift|gg|xyz|top|click|site|link|club|co|ru)", "fake Discord domain"),
    ("url", 45, r"st[e3]a?r?n?c[o0]mm?un[i1l]ty|steamc[o0]mmun[i1l]ty\.(?!com)|steam[-.]?(gift|trade|promo)\w*\.", "fake Steam domain"),
    ("url", 15, r"\b(bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|t\.ly)/", "URL shortener"),
    ("url", 10, r"https?://\S+\.(xyz|top|click|icu|gift|monster|rest|cfd|sbs)\b", "suspicious TLD"),
]

RULES = [(cat, w, re.compile(rx, re.I | re.S), label) for cat, w, rx, label in _R]

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def normalize(text: str) -> str:
    """NFKC fold (full-width/fancy letters), strip accents (OCR often adds them: "specíal"),
    drop zero-width chars, collapse spaces."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).lower()
    text = "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", text).strip()
