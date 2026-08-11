"""Characterization tests for password_strength_checker.

These tests pin down the current behavior of the checker so future changes
that alter scoring or output are caught. They describe what the code does
today, not necessarily ideal behavior.
"""

import math
import subprocess
import sys
from pathlib import Path

import password_strength_checker as psc

SCRIPT = Path(__file__).parent / "password_strength_checker.py"


class TestCharsetSize:
    def test_empty_password_has_zero_pool(self):
        assert psc.charset_size("") == 0

    def test_lowercase_only(self):
        assert psc.charset_size("abc") == 26

    def test_uppercase_only(self):
        assert psc.charset_size("ABC") == 26

    def test_digits_only(self):
        assert psc.charset_size("123") == 10

    def test_symbols_only(self):
        assert psc.charset_size("!@#") == 32

    def test_all_four_categories(self):
        assert psc.charset_size("aA1!") == 94


class TestEstimatedEntropyBits:
    def test_empty_password(self):
        assert psc.estimated_entropy_bits("") == 0.0

    def test_lowercase_word(self):
        assert psc.estimated_entropy_bits("abcd") == 4 * math.log2(26)

    def test_full_variety(self):
        assert psc.estimated_entropy_bits("aA1!") == 4 * math.log2(94)


class TestContainsSequence:
    def test_alphabet_run(self):
        assert psc.contains_sequence("xxabcdxx")

    def test_reversed_run_detected(self):
        assert psc.contains_sequence("dcba")

    def test_digit_run(self):
        assert psc.contains_sequence("pass1234")

    def test_keyboard_row_run(self):
        assert psc.contains_sequence("qwer")

    def test_three_char_run_is_not_enough_by_default(self):
        assert not psc.contains_sequence("abc")

    def test_min_len_override(self):
        assert psc.contains_sequence("abc", min_len=3)

    def test_unrelated_letters(self):
        assert not psc.contains_sequence("kwmzpbvg")


class TestHasRepeatedPattern:
    def test_triple_char(self):
        assert psc.has_repeated_pattern("aaa")

    def test_double_char_alone_is_fine(self):
        assert not psc.has_repeated_pattern("aab")

    def test_repeated_chunk(self):
        assert psc.has_repeated_pattern("ababab")

    def test_two_chunk_repeat(self):
        assert psc.has_repeated_pattern("xyxy")

    def test_no_repetition(self):
        assert not psc.has_repeated_pattern("abcdef")


class TestScorePassword:
    def test_strong_password(self):
        result = psc.score_password("MyTestPass123!")
        assert result.score == 80
        assert result.max_score == 100
        assert result.rating == "Strong"
        assert result.explanations == [
            "+30: Length is 12-15 characters (strong).",
            "+25: Character variety (4/4 categories used).",
            "+25: Estimated entropy is 91.8 bits (very high).",
        ]

    def test_common_word_penalty(self):
        result = psc.score_password("password")
        assert result.score == 1
        assert result.rating == "Weak"
        assert "-15: Contains common weak term: 'password'." in result.explanations

    def test_weak_digits_sequence_clamped_to_zero(self):
        result = psc.score_password("123456")
        assert result.score == 0
        assert result.rating == "Weak"

    def test_digits_only_penalty(self):
        result = psc.score_password("97531")
        assert result.score == 0
        assert "-10: Digits-only passwords are weak." in result.explanations

    def test_empty_password(self):
        result = psc.score_password("")
        assert result.score == 0
        assert result.rating == "Weak"
        assert result.explanations[0] == "+0: Length is below 8 (too short)."

    def test_long_lowercase_passphrase_is_moderate(self):
        result = psc.score_password("correcthorsebatterystaple")
        assert result.score == 71
        assert result.rating == "Moderate"


class TestSuggestImprovements:
    def test_strong_password_gets_only_praise(self):
        assert psc.suggest_improvements("MyTestPass123!") == [
            "Nice work. Consider using a password manager for unique passwords."
        ]

    def test_short_lowercase_gets_category_tips(self):
        tips = psc.suggest_improvements("kwm")
        assert "Use at least 12 characters (16+ is better)." in tips
        assert "Add uppercase letters." in tips
        assert "Add numbers." in tips
        assert "Add symbols (for example: !@#$%)." in tips

    def test_common_word_tip(self):
        tips = psc.suggest_improvements("password")
        assert "Avoid common words like 'password' or 'qwerty'." in tips

    def test_sequence_and_repetition_tips(self):
        tips = psc.suggest_improvements("aaaa1234")
        assert "Avoid predictable sequences like '1234' or 'abcd'." in tips
        assert "Avoid repeated patterns like 'aaaa' or 'ababab'." in tips


class TestCLI:
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=True,
        )

    def test_password_masked_by_default(self):
        result = self.run_cli("Secret123!x")
        assert "Password: ***********" in result.stdout
        assert "Secret123!x" not in result.stdout
        assert "Score:" in result.stdout
        assert "Rating:" in result.stdout

    def test_show_password_flag(self):
        result = self.run_cli("Secret123!x", "--show-password")
        assert "Password: Secret123!x" in result.stdout
