"""Secure random password and passphrase generation."""

import math
import secrets
import string

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

# 256 short, easy-to-type words, so each word adds exactly 8 bits of randomness.
# Real passphrase tools use a list of 7,776 words (about 12.9 bits per word).
WORDS = (
    "acorn amber anchor angle apple arrow aspen atlas badge baker banjo basil beach "
    "berry birch blaze bloom boat bolt bonus brave bread brick bridge brook brush "
    "cabin cable camel candy canoe cargo carpet castle cedar chalk charm chess "
    "chief cider cliff clock cloud clover coast cobra cocoa comet coral cosmos "
    "cotton crane creek crown crystal daisy dance delta denim desert diamond "
    "dolphin dragon dream drift eagle earth echo elbow ember engine fabric falcon "
    "farm feather fern ferry field finch flame flint flute forest fox frost fruit "
    "galaxy garden garlic ginger glacier globe gold grape gravel grove guitar "
    "habit hammer harbor hawk hazel heart hedge helmet honey horizon island ivory "
    "jacket jaguar jelly jewel jungle kernel kettle kite koala ladder lagoon "
    "lantern laser lemon lilac linen lizard lotus lunar magnet mango maple marble "
    "meadow melon mirror mist moon moss motor mountain mule noodle north nutmeg "
    "oasis ocean olive onion orange orbit otter oyster paddle panda paper parrot "
    "peach pearl pepper piano pillow pine planet plum pocket pond poppy prairie "
    "pumpkin puzzle quartz quill rabbit rain raven reef ribbon river robin rocket "
    "saddle saffron sailor salmon sand scarlet shadow shell silver sketch slate "
    "spark spice spider spring spruce square stable star stone storm sugar summit "
    "sunset swan tablet tiger timber tomato torch trail tulip tunnel turtle valley "
    "velvet violet walnut water willow window winter wizard wolf yacht yellow zebra "
    "anvil bamboo cactus dune fjord gecko harp igloo jade kiwi lava maze nectar opal "
    "pebble quail radar sage tundra urchin vine wagon yarn zinc canyon beacon cobalt "
    "dusk glimmer"
).split()

assert len(WORDS) == len(set(WORDS)), "duplicate words in WORDS"
assert len(WORDS) == 256, "WORDS must contain exactly 256 words"


def generate_password(length: int = 16) -> str:
    """Random password that always contains all four character types."""
    if length < 8:
        raise ValueError("length must be at least 8")
    groups = [LOWER, UPPER, DIGITS, SYMBOLS]
    chars = [secrets.choice(group) for group in groups]  # one of each type
    alphabet = "".join(groups)
    chars += [secrets.choice(alphabet) for _ in range(length - len(groups))]
    secrets.SystemRandom().shuffle(chars)  # so the guaranteed ones are not always first
    return "".join(chars)


def password_entropy(length: int) -> float:
    """Approximate bits of randomness in a generated password."""
    alphabet_size = len(LOWER + UPPER + DIGITS + SYMBOLS)
    return round(length * math.log2(alphabet_size), 1)


def generate_passphrase(words: int = 6, separator: str = "-") -> str:
    """Random words joined together, for example 'maple-river-lantern-...'."""
    if words < 4:
        raise ValueError("use at least 4 words")
    return separator.join(secrets.choice(WORDS) for _ in range(words))


def passphrase_entropy(words: int) -> float:
    """Real bits of randomness, based on the size of the word list."""
    return round(words * math.log2(len(WORDS)), 1)


if __name__ == "__main__":
    print("Words in list:", len(WORDS))
    print("Password:  ", generate_password(16), "|", password_entropy(16), "bits")
    print("Passphrase:", generate_passphrase(6), "|", passphrase_entropy(6), "bits")