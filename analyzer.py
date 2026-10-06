"""PassGuard analyzer engine.

Pipeline
--------
1. Rule checks        - length and character classes.
2. Pattern detection  - common passwords, leetspeak, dictionary words,
                        sequences, repeats, keyboard walks, years.
3. Entropy            - length * log2(pool), where every detected pattern is
                        priced at a small fixed cost instead of its raw bits.
4. Score & level      - 0-100 score, five verdict levels, explanations.
5. Crack-time         - assumes an offline attack at 10 billion guesses/second.

The password is only ever held in local variables. It is never stored,
logged or returned inside the result.
"""
from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass

from data import COMMON_PASSWORDS, DICTIONARY_WORDS, KEYBOARD_ROWS, LEET_MAP

GUESSES_PER_SECOND = 10_000_000_000  # offline attack, fast hash
MAX_LENGTH = 128
SYMBOL_POOL = 33  # printable ASCII symbols + space

LEVELS = [  # (minimum score, label)
    (80, "Very Strong"),
    (60, "Strong"),
    (40, "Fair"),
    (20, "Weak"),
    (0, "Very Weak"),
]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
@dataclass
class Match:
    start: int
    end: int          # exclusive
    kind: str         # word | leet-word | sequence | repeat | keyboard | year
    bits: float       # cost of this segment in entropy bits
    text: str

    @property
    def length(self) -> int:
        return self.end - self.start


def char_pool(password: str) -> int:
    """Size of the alphabet the password appears to draw from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += SYMBOL_POOL
    return pool


def de_leet(text: str) -> str:
    return "".join(LEET_MAP.get(c, c) for c in text.lower())


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "Instantly"
    units = [
        ("year", 365.25 * 24 * 3600),
        ("day", 24 * 3600),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    big = [
        (1e18, "quintillion years"), (1e15, "quadrillion years"),
        (1e12, "trillion years"), (1e9, "billion years"),
        (1e6, "million years"), (1e3, "thousand years"),
    ]
    year = units[0][1]
    years = seconds / year
    if years >= 1e21:
        return "Longer than the age of the universe"
    for threshold, label in big:
        if years >= threshold:
            return f"{years / threshold:,.0f} {label}"
    for name, size in units:
        if seconds >= size:
            n = int(seconds // size)
            return f"{n:,} {name}{'s' if n != 1 else ''}"
    return "Instantly"


def crack_time(entropy_bits: float) -> tuple[float, str]:
    # On average an attacker finds the password after trying half the space.
    seconds = (2 ** min(entropy_bits, 200)) / 2 / GUESSES_PER_SECOND
    return seconds, format_duration(seconds)


# --------------------------------------------------------------------------
# pattern detection
# --------------------------------------------------------------------------
def find_sequences(pw: str) -> list[Match]:
    """Runs of 3+ consecutive characters going up or down (abc, 987)."""
    out, i, n = [], 0, len(pw)
    while i < n - 2:
        step = ord(pw[i + 1].lower()) - ord(pw[i].lower())
        if step in (1, -1):
            j = i + 1
            while j + 1 < n and ord(pw[j + 1].lower()) - ord(pw[j].lower()) == step:
                j += 1
            run = j - i + 1
            if run >= 3 and pw[i:j + 1].isalnum():
                out.append(Match(i, j + 1, "sequence", 4 + math.log2(run), pw[i:j + 1]))
                i = j + 1
                continue
        i += 1
    return out


def find_repeats(pw: str) -> list[Match]:
    """3+ identical characters in a row (aaa, 1111)."""
    return [
        Match(m.start(), m.end(), "repeat", 4 + math.log2(len(m.group())), m.group())
        for m in re.finditer(r"(.)\1{2,}", pw)
    ]


def find_keyboard(pw: str) -> list[Match]:
    """3+ characters that sit next to each other on a keyboard row."""
    low, out = pw.lower(), []
    for row in KEYBOARD_ROWS:
        for seq in (row, row[::-1]):
            size = len(seq)
            i = 0
            while i <= size - 3:
                length = 0
                for L in range(size - i, 2, -1):
                    if seq[i:i + L] in low:
                        length = L
                        break
                if length:
                    piece = seq[i:i + length]
                    start = low.find(piece)
                    out.append(Match(start, start + length, "keyboard",
                                     6 + math.log2(length), pw[start:start + length]))
                    i += length
                else:
                    i += 1
    # a pure digit run such as 12345 is reported as a sequence, not keyboard
    return [m for m in out if not m.text.isdigit()]


def find_years(pw: str) -> list[Match]:
    return [
        Match(m.start(1), m.end(1), "year", 7, m.group(1))
        for m in re.finditer(r"(?<!\d)((?:19|20)\d{2})(?!\d)", pw)
    ]


def find_words(pw: str) -> list[Match]:
    """Dictionary words, including leetspeak versions (p@ssw0rd -> password)."""
    plain, leet = pw.lower(), de_leet(pw)
    out = []
    for word in sorted(DICTIONARY_WORDS, key=len, reverse=True):
        if len(word) < 4:
            continue
        for text, kind, bits in ((plain, "word", 14), (leet, "leet-word", 16)):
            start = text.find(word)
            while start != -1:
                # a leet match only counts if something was actually substituted
                original = pw[start:start + len(word)]
                if kind == "word" or original.lower() != word:
                    out.append(Match(start, start + len(word), kind, bits, original))
                start = text.find(word, start + 1)
    return out


def pick_non_overlapping(matches: list[Match]) -> list[Match]:
    """Prefer longer matches, then cheaper ones; drop anything that overlaps."""
    chosen: list[Match] = []
    taken: set[int] = set()
    for m in sorted(matches, key=lambda m: (-m.length, m.bits)):
        span = set(range(m.start, m.end))
        if span & taken:
            continue
        chosen.append(m)
        taken |= span
    return sorted(chosen, key=lambda m: m.start)


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------
def analyze(password: str) -> dict:
    n = len(password)
    checks = {
        "length": n >= 12,
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    if n == 0:
        return _result(0, "Very Weak", 0.0, "Instantly", checks, [], [
            "Type a password to analyze it."])

    pool = char_pool(password)
    per_char = math.log2(pool)
    raw_entropy = n * per_char

    findings: list[str] = []
    suggestions: list[str] = []

    low = password.lower()
    is_common = low in COMMON_PASSWORDS
    is_common_leet = (not is_common) and de_leet(password) in COMMON_PASSWORDS

    if is_common:
        findings.append("This is one of the most commonly used passwords.")
        suggestions.append("Never use a well-known password; choose something random.")
        entropy = min(raw_entropy, 10.0)
        cap = 5
    elif is_common_leet:
        findings.append("This is a common password with look-alike symbols "
                        "(leetspeak such as @ for a, 0 for o). Attackers try these first.")
        suggestions.append("Swapping letters for symbols does not make a common word safe.")
        entropy = min(raw_entropy, 14.0)
        cap = 15
    else:
        cap = 100
        matches = pick_non_overlapping(
            find_words(password) + find_sequences(password) + find_repeats(password)
            + find_keyboard(password) + find_years(password)
        )
        covered = sum(m.length for m in matches)
        entropy = (n - covered) * per_char + sum(m.bits for m in matches)

        kinds = {m.kind for m in matches}
        words = [m for m in matches if m.kind in ("word", "leet-word")]
        if words:
            tail = n - sum(m.length for m in words)
            extras = []
            if re.search(r"\d", password) and "year" not in kinds:
                extras.append("digits")
            if "year" in kinds:
                extras.append("a year")
            if re.search(r"[^A-Za-z0-9]", password):
                extras.append("a symbol")
            base = ", ".join(f'"{m.text}"' for m in words)
            if "leet-word" in kinds:
                findings.append(f"Contains the common word {base} written with "
                                "look-alike characters.")
            elif tail > 0 and extras:
                findings.append(f"Built on the common word {base} with "
                                f"{' and '.join(extras)} added.")
            else:
                findings.append(f"Contains the common word {base}.")
            suggestions.append("Avoid dictionary words, names and places, even with "
                               "numbers or symbols added.")
            cap = min(cap, 25 if (tail > 0 or len(words) > 1) else 15)
        if "sequence" in kinds:
            ex = next(m.text for m in matches if m.kind == "sequence")
            findings.append(f'Contains a sequence ("{ex}").')
            suggestions.append("Avoid runs like 123 or abc.")
        if "repeat" in kinds:
            ex = next(m.text for m in matches if m.kind == "repeat")
            findings.append(f'Contains repeated characters ("{ex}").')
            suggestions.append("Avoid repeating the same character.")
        if "keyboard" in kinds:
            ex = next(m.text for m in matches if m.kind == "keyboard")
            findings.append(f'Contains a keyboard pattern ("{ex}").')
            suggestions.append("Avoid keys that sit next to each other, like qwerty.")
        if "year" in kinds and not words:
            ex = next(m.text for m in matches if m.kind == "year")
            findings.append(f'Contains a year ("{ex}"), which is easy to guess.')
            suggestions.append("Avoid birth years and recent years.")
        if matches and covered >= 0.6 * n:
            cap = min(cap, 35)

    # --- rule-based suggestions -------------------------------------------
    if not checks["length"]:
        suggestions.append("Use at least 12 characters; length matters most.")
    if not checks["uppercase"]:
        suggestions.append("Add an uppercase letter.")
    if not checks["lowercase"]:
        suggestions.append("Add a lowercase letter.")
    if not checks["digit"]:
        suggestions.append("Add a digit.")
    if not checks["symbol"]:
        suggestions.append("Add a symbol such as ! # $ %.")
    if n < 8:
        findings.append("Very short: under 8 characters can be brute-forced quickly.")
        cap = min(cap, 20)

    # --- score ------------------------------------------------------------
    entropy = max(0.0, entropy)
    score = min(100, int(round(entropy)))
    score = min(score, cap)
    level = next(label for floor, label in LEVELS if score >= floor)
    _, crack = crack_time(entropy)

    if not findings and level in ("Strong", "Very Strong"):
        findings.append("No common words, sequences or keyboard patterns found.")
    if level != "Very Strong" and not suggestions:
        suggestions.append("Make it longer or use the generator for a random one.")
    if level == "Very Strong" and not suggestions:
        suggestions.append("Looks great. Store it in a password manager and use it on one site only.")

    # de-duplicate while keeping order
    suggestions = list(dict.fromkeys(suggestions))
    return _result(score, level, entropy, crack, checks, findings, suggestions)


def _result(score, level, entropy, crack, checks, findings, suggestions) -> dict:
    return {
        "score": score,
        "level": level,
        "entropy_bits": round(entropy, 1),
        "crack_time": crack,
        "checks": checks,
        "findings": findings,
        "suggestions": suggestions,
    }


# --------------------------------------------------------------------------
# generator
# --------------------------------------------------------------------------
GEN_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate_password(length: int = 16, symbols: bool = True) -> str:
    """Cryptographically secure password with at least one of each class."""
    if not 8 <= length <= 64:
        raise ValueError("length must be between 8 and 64")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        groups.append(GEN_SYMBOLS)
    alphabet = "".join(groups)
    chars = [secrets.choice(g) for g in groups]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
