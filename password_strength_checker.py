#!/usr/bin/env python3
"""
Very basic, beginner-friendly password strength checker CLI.

This tool is for education and self-assessment only.
It does NOT crack passwords or bypass systems.
"""

from __future__ import annotations

import argparse
import math
import re
from dataclasses import dataclass


COMMON_WORDS = {
    "password",
    "admin",
    "welcome",
    "qwerty",
    "letmein",
    "iloveyou",
    "123456",
    "12345678",
    "abc123",
}

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
]


@dataclass
class ScoreResult:
    score: int
    max_score: int
    rating: str
    explanations: list[str]


def charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32  # rough printable symbol set
    return size


def estimated_entropy_bits(password: str) -> float:
    pool = charset_size(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def contains_sequence(password: str, min_len: int = 4) -> bool:
    lower = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i : i + min_len]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def has_repeated_pattern(password: str) -> bool:
    # Examples: "aaaa", "ababab", "1111"
    return bool(re.search(r"(.)\1{2,}", password) or re.search(r"(.{2,})\1+", password))


def score_password(password: str) -> ScoreResult:
    explanations: list[str] = []
    score = 0
    max_score = 100

    # Length scoring (0-40)
    length = len(password)
    if length >= 16:
        score += 40
        explanations.append("+40: Length is 16+ characters (excellent).")
    elif length >= 12:
        score += 30
        explanations.append("+30: Length is 12-15 characters (strong).")
    elif length >= 10:
        score += 20
        explanations.append("+20: Length is 10-11 characters (okay).")
    elif length >= 8:
        score += 10
        explanations.append("+10: Length is 8-9 characters (minimum-ish).")
    else:
        explanations.append("+0: Length is below 8 (too short).")

    # Character variety scoring (0-25)
    categories = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    variety_points = sum(categories) * 6
    if sum(categories) == 4:
        variety_points += 1  # make full variety = 25
    score += variety_points
    explanations.append(
        f"+{variety_points}: Character variety ({sum(categories)}/4 categories used)."
    )

    # Entropy estimate scoring (0-25)
    entropy = estimated_entropy_bits(password)
    if entropy >= 80:
        score += 25
        explanations.append(f"+25: Estimated entropy is {entropy:.1f} bits (very high).")
    elif entropy >= 60:
        score += 18
        explanations.append(f"+18: Estimated entropy is {entropy:.1f} bits (good).")
    elif entropy >= 40:
        score += 10
        explanations.append(f"+10: Estimated entropy is {entropy:.1f} bits (moderate).")
    else:
        explanations.append(f"+0: Estimated entropy is {entropy:.1f} bits (low).")

    # Penalties (up to -30)
    lower = password.lower()
    for word in COMMON_WORDS:
        if word in lower:
            score -= 15
            explanations.append(f"-15: Contains common weak term: '{word}'.")
            break

    if contains_sequence(password):
        score -= 10
        explanations.append("-10: Contains keyboard/alphabet/number sequence.")

    if has_repeated_pattern(password):
        score -= 8
        explanations.append("-8: Contains repeated characters/patterns.")

    if re.fullmatch(r"\d+", password):
        score -= 10
        explanations.append("-10: Digits-only passwords are weak.")

    score = max(0, min(max_score, score))

    if score >= 80:
        rating = "Strong"
    elif score >= 55:
        rating = "Moderate"
    else:
        rating = "Weak"

    return ScoreResult(score=score, max_score=max_score, rating=rating, explanations=explanations)


def suggest_improvements(password: str) -> list[str]:
    tips: list[str] = []

    if len(password) < 12:
        tips.append("Use at least 12 characters (16+ is better).")
    if not any(c.islower() for c in password):
        tips.append("Add lowercase letters.")
    if not any(c.isupper() for c in password):
        tips.append("Add uppercase letters.")
    if not any(c.isdigit() for c in password):
        tips.append("Add numbers.")
    if not any(not c.isalnum() for c in password):
        tips.append("Add symbols (for example: !@#$%).")
    if contains_sequence(password):
        tips.append("Avoid predictable sequences like '1234' or 'abcd'.")
    if has_repeated_pattern(password):
        tips.append("Avoid repeated patterns like 'aaaa' or 'ababab'.")

    lower = password.lower()
    if any(word in lower for word in COMMON_WORDS):
        tips.append("Avoid common words like 'password' or 'qwerty'.")

    if not tips:
        tips.append("Nice work. Consider using a password manager for unique passwords.")

    return tips


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Basic password strength checker with explainable scoring."
    )
    parser.add_argument("password", nargs="?", help="Password to evaluate")
    parser.add_argument(
        "--show-password",
        action="store_true",
        help="Print the raw password in output (default is hidden).",
    )
    args = parser.parse_args()

    password = args.password
    if password is None:
        try:
            import getpass

            password = getpass.getpass("Enter password to check: ")
        except Exception:
            password = input("Enter password to check: ")

    result = score_password(password)

    shown = password if args.show_password else "*" * len(password)
    print("\nPassword strength report")
    print("-" * 26)
    print(f"Password: {shown}")
    print(f"Score:    {result.score}/{result.max_score}")
    print(f"Rating:   {result.rating}")
    print("\nWhy this score:")
    for line in result.explanations:
        print(f"  - {line}")

    print("\nHow to improve:")
    for tip in suggest_improvements(password):
        print(f"  - {tip}")


if __name__ == "__main__":
    main()
