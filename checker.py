"""Core password analysis: score, weaknesses and a rough guessing-time estimate."""

import math
import re
import string
from dataclasses import dataclass, field

# A small sample list. Real tools check against lists of millions of leaked passwords.
COMMON_PASSWORDS = {
    "password", "password1", "password12", "password123", "pass1234",
    "123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234",
    "123123", "123321", "654321", "987654321", "111111", "000000", "121212",
    "qwerty", "qwerty123", "qwertyuiop", "1q2w3e4r", "zaq12wsx", "abc123",
    "letmein", "welcome", "welcome1", "admin", "admin123", "login", "hello123",
    "iloveyou", "monkey", "dragon", "football", "master", "sunshine", "princess",
    "superman", "batman", "trustno1", "shadow", "freedom", "whatever", "starwars",
    "springbok", "mzansi", "pretoria", "soweto",
    "summer", "winter", "autumn", "spring",
}

# Runs of keys or letters that attackers try first.
SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz",
]

# Common character swaps, like p@ssw0rd. The digit 1 can stand for "i" or "l".
_SWAPS = {"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t", "!": "i"}
LEET_VARIANTS = [
    str.maketrans({**_SWAPS, "1": "i"}),
    str.maketrans({**_SWAPS, "1": "l"}),
]

GUESSES_PER_SECOND = 10_000_000_000  # an attacker with fast hardware and a weak hash
FULL_SCORE_BITS = 90                 # bits of strength that count as a perfect score


@dataclass
class Result:
    score: int
    rating: str
    bits: float
    crack_time: str
    issues: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)


def character_pool(password: str) -> int:
    """How many different characters an attacker must consider per position."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return pool


def find_sequence(password: str, run: int = 4):
    """Return a keyboard or alphabet run (like 'qwer' or '4321') if there is one."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i:i + run] in lowered:
                    return s[i:i + run]
    return None


def check_common(password: str):
    """Return 'exact', 'swapped' or 'contains' if the password is a known one."""
    lowered = password.lower()
    trim = string.digits + string.punctuation

    def known(text):
        return text in COMMON_PASSWORDS or text.rstrip(trim) in COMMON_PASSWORDS

    if known(lowered):
        return "exact"
    variants = [lowered.translate(t) for t in LEET_VARIANTS]
    if any(known(v) for v in variants):
        return "swapped"
    for word in COMMON_PASSWORDS:
        if len(word) >= 6 and any(word in v for v in [lowered] + variants):
            return "contains"
    return None


def format_duration(seconds: float) -> str:
    """Turn a number of seconds into plain words."""
    if seconds < 1:
        return "instantly"
    units = [
        ("second", 60), ("minute", 60), ("hour", 24), ("day", 365),
        ("year", 1000), ("thousand years", 1000), ("million years", 1000),
    ]
    value = seconds
    for name, size in units:
        if value < size:
            n = int(value)
            return f"about {n} {name}{'' if n == 1 or ' ' in name else 's'}"
        value /= size
    return "billions of years"


def analyse(password: str) -> Result:
    """Work out how strong a password is and why."""
    if not password:
        return Result(0, "Very weak", 0.0, "instantly", ["The password is empty."],
                      ["Type a password to check."])

    issues, suggestions = [], []
    pool = character_pool(password)
    bits = len(password) * math.log2(pool)

    common = check_common(password)
    if common == "exact":
        bits = min(bits, 12)
        issues.append("This is a very common password.")
        suggestions.append("Do not use well-known passwords. They are guessed first.")
    elif common == "swapped":
        bits = min(bits, 20)
        issues.append("This is a common password with letters swapped for symbols.")
        suggestions.append("Swaps like @ for a or 0 for o are well known to attackers.")
    elif common == "contains":
        bits = max(bits - 25, 0)
        issues.append("This contains a common password or word.")
        suggestions.append("Avoid common words, even inside longer passwords.")

    run = find_sequence(password)
    if run:
        bits = max(bits - 20, 0)
        issues.append(f"This contains an easy-to-guess sequence ('{run}').")
        suggestions.append("Avoid keyboard rows and runs like 1234 or abcd.")

    if re.search(r"(.)\1{2,}", password):
        bits = max(bits - 10, 0)
        issues.append("This repeats the same character three or more times in a row.")
        suggestions.append("Avoid repeated characters like 'aaa'.")

    if re.search(r"(19|20)\d{2}$", password):
        bits = max(bits - 15, 0)
        issues.append("Ending with a year is a very common pattern.")
        suggestions.append("Do not add a year or birthday to the end of a word.")

    if len(password) < 12:
        issues.append(f"Only {len(password)} characters. Longer is much stronger.")
        suggestions.append("Use at least 12 characters, or a passphrase of 4 or more words.")

    score = max(0, min(100, round(bits / FULL_SCORE_BITS * 100)))
    if score < 25:
        rating = "Very weak"
    elif score < 45:
        rating = "Weak"
    elif score < 65:
        rating = "Fair"
    elif score < 85:
        rating = "Strong"
    else:
        rating = "Very strong"

    crack = format_duration(2.0 ** min(bits, 1000) / 2 / GUESSES_PER_SECOND)
    return Result(score, rating, round(bits, 1), crack, issues, suggestions)


if __name__ == "__main__":
    samples = [
        "password", "P@ssw0rd", "qwerty123", "abcdefgh", "Summer2024",
        "aB3$kL9!", "Tr1cky!Lock#42", "maple river lantern wobble",
    ]
    for pw in samples:
        r = analyse(pw)
        print(f"{pw:30} {r.score:3}  {r.rating:11} {r.crack_time}")