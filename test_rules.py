import sqlite3

from scambot.decision import score_text
from scambot.learner import HAM, SCAM, Learner

SCAMS = [
    "Congratulations! You have won free Nitro. Claim your gift now: discord-nitro.xyz",
    "I made $14,000 in 3 days trading crypto. DM me to learn how, message me on Telegram @bigprofit",
    "Hiring now! Earn $500 per day, no experience needed. Contact us on WhatsApp",
    "Elon Musk BTC giveaway: send 0.1 BTC and receive 0.2 BTC back. Limited time!",
    "Your account will be suspended. Verify your account immediately: bit.ly/xyz",
    "Recover your lost crypto funds, guaranteed returns, contact our expert recovery team",
    "ATTENTION: You have been fined $85.22 for failing to return Order No. #23442314. Please log in below "
    "within 48 hours to pay this fine or to apply for a waive. https://shorturl.at/hlMNT",
    "USPS: Your package could not be delivered due to an unpaid customs fee. Pay the fee within 24 hours: usps-redeliver.top",
    "E-ZPass final notice: you have an unpaid toll balance of $6.99. Pay your balance now to avoid a fine: bit.ly/ezp",
    "PayPal: you were charged $499.99. If this was not you, log in below to claim a refund: paypa1.co/support",
    "hey sorry I accidentally reported your account, you need to contact the discord support staff before you get banned",
    "yo can you try my new game? its in beta, password for the zip is 2024, just run the exe",
    "I have your private videos. Pay $300 in bitcoin or I will send them to your friends and family",
    "Your computer is infected! Call Microsoft support team immediately at 1-844-555-0199",
    "MrBeast giveaway! First 1000 people get $500, claim your prize at mrbeast-gift.top",
    "Buy Google Play gift cards and send me photos of the codes to pay the fee, urgent",
    "To withdraw your profits you need to pay the tax fee first, then funds unlock within 24 hours",
    "Free robux! Click here and log in to claim 10000 robux: bit.ly/rbx",
]
SAFE = [
    "hey does anyone want to play valorant tonight?",
    "check out my new art commission, I'm open for work",
    "the giveaway winner will be picked at random, join our server event",
    "I bought bitcoin last year lol",
    "my amazon order #112233445 finally arrived, the package was late but it's fine",
    "got a parking fine today, gotta pay it within 30 days ugh",
    "attention everyone: the event starts in 2 hours, log in to the game now",
    "I returned my order to amazon and got a refund, took 5 days",
    "mrbeast's new video was crazy",
    "never scan QR codes people send you, discord staff will never ask for your password",
    "I'm making a game in unity, anyone want to see screenshots?",
    "my bank app is down again, anyone else?",
    "call me at 7 if you want to play",
    "I bought a steam gift card for my brother's birthday",
]

fails = 0
for t in SCAMS:
    s, m, _ = score_text(t)
    if s < 50:
        fails += 1
        print("MISSED", s, t, m)
for t in SAFE:
    s, m, _ = score_text(t)
    if s >= 50:
        fails += 1
        print("FALSE ALARM", s, t, m)

# Learned model: trains on seeds, then should lean the right way on unseen text.
lr = Learner(sqlite3.connect(":memory:"))
p_scam = lr.prob_scam("free nitro giveaway, claim your gift before it expires, login with discord")
p_ham = lr.prob_scam("anyone want to play minecraft later tonight? the server is back up")
print(f"model: scam-like {p_scam:.2f}, normal {p_ham:.2f}")
assert p_scam is not None and p_ham is not None and p_scam > 0.8 and p_ham < 0.3
# Moderator feedback shifts it.
before = lr.prob_scam("join my crypto signals group for daily pumps")
for _ in range(3):
    lr.add("join my crypto signals group for daily pumps, 10x guaranteed", SCAM, "mod")
after = lr.prob_scam("join my crypto signals group for daily pumps")
print(f"after learning: {before:.2f} -> {after:.2f}")
assert before is not None and after is not None and after > before

assert fails == 0, f"{fails} failures"
print("ok")
