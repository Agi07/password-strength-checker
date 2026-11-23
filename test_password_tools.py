"""Automated tests for the password strength checker. Run: python -m unittest -v"""

import re
import string
import unittest
from unittest.mock import patch

import checker
import generator
import main


class TestCommonPasswords(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        result = checker.analyse("password")
        self.assertEqual(result.rating, "Very weak")
        self.assertEqual(result.crack_time, "instantly")

    def test_common_password_with_digits_added_is_still_caught(self):
        self.assertEqual(checker.check_common("Password99!"), "exact")

    def test_symbol_swaps_are_caught(self):
        self.assertEqual(checker.check_common("P@ssw0rd"), "swapped")

    def test_common_word_inside_longer_password_is_caught(self):
        self.assertEqual(checker.check_common("xxpretoriaxx"), "contains")

    def test_unusual_password_is_not_flagged(self):
        self.assertIsNone(checker.check_common("Tr1cky!Lock#42"))


class TestPatterns(unittest.TestCase):
    def test_keyboard_row_detected(self):
        self.assertEqual(checker.find_sequence("xxqwerxx"), "qwer")

    def test_reversed_run_detected(self):
        self.assertIsNotNone(checker.find_sequence("zz4321zz"))

    def test_alphabet_run_detected(self):
        self.assertEqual(checker.find_sequence("abcdQ9"), "abcd")

    def test_no_sequence_in_random_text(self):
        self.assertIsNone(checker.find_sequence("Tr1cky!Lock#42"))

    def test_repeated_characters_flagged(self):
        issues = checker.analyse("Zk9!aaaB#x").issues
        self.assertTrue(any("repeats" in issue for issue in issues))

    def test_year_at_end_flagged(self):
        issues = checker.analyse("Tr1cky!Lock#2024").issues
        self.assertTrue(any("year" in issue for issue in issues))


class TestScoring(unittest.TestCase):
    def test_empty_password(self):
        result = checker.analyse("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.rating, "Very weak")

    def test_strong_random_password_scores_high(self):
        result = checker.analyse("Tr1cky!Lock#42")
        self.assertGreaterEqual(result.score, 85)
        self.assertEqual(result.rating, "Very strong")

    def test_short_random_password_is_only_fair(self):
        self.assertEqual(checker.analyse("aB3$kL9!").rating, "Fair")

    def test_longer_is_stronger(self):
        self.assertGreater(
            checker.analyse("Tr1cky!Lock#42").score, checker.analyse("Tr1cky!").score
        )

    def test_score_always_between_0_and_100(self):
        samples = ["", "a", "password", "P@ssw0rd", "Tr1cky!Lock#42", "x" * 200,
                   "qwerty123", "!" * 50]
        for sample in samples:
            score = checker.analyse(sample).score
            self.assertTrue(0 <= score <= 100, sample)

    def test_weak_password_gets_suggestions(self):
        result = checker.analyse("abc")
        self.assertTrue(result.issues)
        self.assertTrue(result.suggestions)

    def test_strong_password_has_no_issues(self):
        self.assertEqual(checker.analyse("Tr1cky!Lock#42").issues, [])


class TestDuration(unittest.TestCase):
    def test_under_one_second(self):
        self.assertEqual(checker.format_duration(0.2), "instantly")

    def test_seconds_minutes_days(self):
        self.assertEqual(checker.format_duration(30), "about 30 seconds")
        self.assertEqual(checker.format_duration(120), "about 2 minutes")
        self.assertEqual(checker.format_duration(3 * 24 * 3600), "about 3 days")

    def test_singular_year(self):
        self.assertEqual(checker.format_duration(366 * 24 * 3600), "about 1 year")

    def test_huge_numbers(self):
        self.assertEqual(checker.format_duration(1e30), "billions of years")


class TestGenerator(unittest.TestCase):
    def test_password_has_requested_length(self):
        for length in (8, 16, 40):
            self.assertEqual(len(generator.generate_password(length)), length)

    def test_password_always_contains_every_character_type(self):
        for _ in range(300):
            pw = generator.generate_password(8)
            self.assertTrue(re.search(r"[a-z]", pw), pw)
            self.assertTrue(re.search(r"[A-Z]", pw), pw)
            self.assertTrue(re.search(r"\d", pw), pw)
            self.assertTrue(any(c in generator.SYMBOLS for c in pw), pw)

    def test_password_uses_only_allowed_characters(self):
        allowed = set(string.ascii_letters + string.digits + generator.SYMBOLS)
        self.assertTrue(set(generator.generate_password(64)) <= allowed)

    def test_passwords_are_not_repeated(self):
        passwords = {generator.generate_password(16) for _ in range(200)}
        self.assertEqual(len(passwords), 200)

    def test_too_short_password_is_refused(self):
        with self.assertRaises(ValueError):
            generator.generate_password(7)

    def test_generated_passwords_pass_the_checker(self):
        for _ in range(20):
            result = checker.analyse(generator.generate_password(16))
            self.assertGreaterEqual(result.score, 85)

    def test_word_list_is_256_unique_words(self):
        self.assertEqual(len(generator.WORDS), 256)
        self.assertEqual(len(set(generator.WORDS)), 256)

    def test_passphrase_word_count_and_source(self):
        words = generator.generate_passphrase(6).split("-")
        self.assertEqual(len(words), 6)
        self.assertTrue(all(word in generator.WORDS for word in words))

    def test_too_few_words_refused(self):
        with self.assertRaises(ValueError):
            generator.generate_passphrase(3)

    def test_passphrase_entropy_is_8_bits_per_word(self):
        self.assertEqual(generator.passphrase_entropy(6), 48.0)


class TestInterface(unittest.TestCase):
    def test_bar_empty_and_full(self):
        self.assertEqual(main.bar(0), "[" + "." * main.BAR_WIDTH + "]")
        self.assertEqual(main.bar(100), "[" + "#" * main.BAR_WIDTH + "]")

    def test_ask_number_uses_default_on_enter(self):
        with patch("builtins.input", return_value=""):
            self.assertEqual(main.ask_number("Length", 16, 8, 64), 16)

    def test_ask_number_accepts_valid_value(self):
        with patch("builtins.input", return_value="20"):
            self.assertEqual(main.ask_number("Length", 16, 8, 64), 20)

    def test_ask_number_rejects_out_of_range_and_text(self):
        for bad in ("3", "999", "abc", "-5"):
            with patch("builtins.input", return_value=bad):
                self.assertEqual(main.ask_number("Length", 16, 8, 64), 16, bad)


if __name__ == "__main__":
    unittest.main()