"""
tests/test_analyzer.py
Unit tests for the Password Strength Analyzer backend.

Run:  pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from app import analyze_password, detect_patterns, estimate_crack_times, check_hibp


class TestBasicCriteria:

    def test_empty_password(self):
        r = analyze_password("")
        assert r["length"] == 0
        assert r["level"] == "none"
        assert r["score"] == 0
        assert r["entropy"] == 0

    def test_short_password(self):
        r = analyze_password("abc")
        assert r["length"] == 3
        assert r["criteria"]["meets_min"] is False
        assert r["criteria"]["meets_rec"] is False
        assert r["level"] == "weak"

    def test_minimum_length(self):
        r = analyze_password("abcdefgh")
        assert r["criteria"]["meets_min"] is True
        assert r["criteria"]["meets_rec"] is False

    def test_recommended_length(self):
        r = analyze_password("abcdefghijkl")
        assert r["criteria"]["meets_min"] is True
        assert r["criteria"]["meets_rec"] is True

    def test_uppercase_detection(self):
        r = analyze_password("PASSWORD")
        assert r["criteria"]["has_upper"] is True
        assert r["criteria"]["has_lower"] is False

    def test_lowercase_detection(self):
        r = analyze_password("password")
        assert r["criteria"]["has_lower"] is True
        assert r["criteria"]["has_upper"] is False

    def test_number_detection(self):
        r = analyze_password("pass1234")
        assert r["criteria"]["has_number"] is True

    def test_symbol_detection(self):
        r = analyze_password("pass@word")
        assert r["criteria"]["has_symbol"] is True

    def test_no_symbol(self):
        r = analyze_password("Password1")
        assert r["criteria"]["has_symbol"] is False

    def test_all_criteria_met(self):
        r = analyze_password("Str0ng!Pass#2024")
        c = r["criteria"]
        assert c["meets_min"]  is True
        assert c["meets_rec"]  is True
        assert c["has_upper"]  is True
        assert c["has_lower"]  is True
        assert c["has_number"] is True
        assert c["has_symbol"] is True


class TestScoringAndLevels:

    def test_common_password_score_capped(self):
        r = analyze_password("password")
        assert r["score"] <= 15
        assert r["level"] == "weak"
        assert r["is_common"] is True

    def test_common_password_123456(self):
        r = analyze_password("123456")
        assert r["is_common"] is True
        assert r["level"] == "weak"

    def test_strong_password_level(self):
        r = analyze_password("Str0ng!Pass#2024XY")
        assert r["level"] in ("strong", "vstrong")
        assert r["score"] >= 80

    def test_fair_password(self):
        r = analyze_password("password1A")
        assert r["level"] in ("weak", "fair")

    def test_score_max_100(self):
        r = analyze_password("Tr0ub4dor&3-correct-horse")
        assert r["score"] <= 100

    def test_score_min_0(self):
        r = analyze_password("")
        assert r["score"] >= 0

    def test_entropy_increases_with_length(self):
        r_short = analyze_password("Abc1!")
        r_long  = analyze_password("Abc1!Abc1!Abc1!")
        assert r_long["entropy"] > r_short["entropy"]

    def test_entropy_increases_with_diversity(self):
        r_lower  = analyze_password("aaaaaaaaaaa")
        r_mixed  = analyze_password("aA1!aA1!aA1")
        assert r_mixed["entropy"] > r_lower["entropy"]


class TestFeedback:

    def test_empty_feedback_has_tip(self):
        r = analyze_password("")
        assert len(r["feedback"]) >= 1
        assert r["feedback"][0]["type"] == "tip"

    def test_common_password_warn_feedback(self):
        r = analyze_password("password")
        types = [f["type"] for f in r["feedback"]]
        assert "warn" in types

    def test_short_password_warn_feedback(self):
        r = analyze_password("abc")
        types = [f["type"] for f in r["feedback"]]
        assert "warn" in types

    def test_strong_password_has_good_feedback(self):
        r = analyze_password("Str0ng!Pass#2024XY")
        types = [f["type"] for f in r["feedback"]]
        assert "good" in types

    def test_feedback_icons_present(self):
        r = analyze_password("hello")
        for fb in r["feedback"]:
            assert "icon" in fb
            assert len(fb["icon"]) > 0

    def test_feedback_text_nonempty(self):
        r = analyze_password("TestPass1!")
        for fb in r["feedback"]:
            assert len(fb["text"]) > 0


class TestPatternDetection:

    def test_repeated_chars_detected(self):
        patterns = detect_patterns("aaabbbccc")
        types = [p["type"] for p in patterns]
        assert "repeated_chars" in types

    def test_sequential_numbers_detected(self):
        patterns = detect_patterns("abc12345xyz")
        types = [p["type"] for p in patterns]
        assert "sequential_numbers" in types

    def test_keyboard_sequence_detected(self):
        patterns = detect_patterns("qwerty123")
        types = [p["type"] for p in patterns]
        assert "keyboard_sequence" in types

    def test_dictionary_word_detected(self):
        patterns = detect_patterns("password123")
        types = [p["type"] for p in patterns]
        assert "dictionary_word" in types

    def test_year_pattern_detected(self):
        patterns = detect_patterns("mypass1995")
        types = [p["type"] for p in patterns]
        assert "year_pattern" in types

    def test_all_digits_detected(self):
        patterns = detect_patterns("12345678")
        types = [p["type"] for p in patterns]
        assert "all_digits" in types

    def test_all_letters_detected(self):
        patterns = detect_patterns("abcdefghij")
        types = [p["type"] for p in patterns]
        assert "all_letters" in types

    def test_strong_password_no_patterns(self):
        patterns = detect_patterns("Tr0ub4dor&3!XpQz")
        high_patterns = [p for p in patterns if p["severity"] == "high"]
        assert len(high_patterns) == 0

    def test_pattern_severity_field(self):
        patterns = detect_patterns("qwerty123aaa")
        for p in patterns:
            assert p["severity"] in ("high", "medium")

    def test_empty_password_no_patterns(self):
        patterns = detect_patterns("")
        assert patterns == []


class TestCrackTimes:

    def test_returns_all_models(self):
        ct = estimate_crack_times(40.0)
        assert "online_throttled"   in ct
        assert "online_unthrottled" in ct
        assert "offline_gpu"        in ct
        assert "offline_botnet"     in ct

    def test_online_slower_than_offline(self):
        ct = estimate_crack_times(40.0)
        assert ct["online_throttled"]["seconds"] > ct["offline_botnet"]["seconds"]

    def test_high_entropy_takes_long_online(self):
        ct = estimate_crack_times(80.0)
        assert ct["online_throttled"]["seconds"] > 1_000_000

    def test_zero_entropy(self):
        ct = estimate_crack_times(0)
        assert ct["online_throttled"]["seconds"] == pytest.approx(0.01, abs=0.05)

    def test_display_string_nonempty(self):
        ct = estimate_crack_times(40.0)
        for key, val in ct.items():
            assert len(val["display"]) > 0

    def test_label_nonempty(self):
        ct = estimate_crack_times(40.0)
        for key, val in ct.items():
            assert len(val["label"]) > 0


class TestReturnStructure:

    def test_all_top_level_keys_present(self):
        r = analyze_password("TestPass1!")
        expected = [
            "score", "entropy", "level", "level_label", "length",
            "is_common", "criteria", "feedback", "patterns",
            "crack_times", "zxcvbn", "hibp", "zxcvbn_available",
        ]
        for key in expected:
            assert key in r, f"Missing key: {key}"

    def test_criteria_keys(self):
        r = analyze_password("TestPass1!")
        expected = ["meets_min", "meets_rec", "has_upper", "has_lower",
                    "has_number", "has_symbol"]
        for key in expected:
            assert key in r["criteria"]

    def test_hibp_is_none_by_default(self):
        r = analyze_password("TestPass1!", check_hibp_api=False)
        assert r["hibp"] is None

    def test_crack_times_present_when_nonempty(self):
        r = analyze_password("TestPass1!")
        assert isinstance(r["crack_times"], dict)
        assert len(r["crack_times"]) > 0

    def test_level_label_matches_level(self):
        mapping = {
            "none":    "—",
            "weak":    "Weak",
            "fair":    "Fair",
            "strong":  "Strong",
            "vstrong": "Very Strong",
        }
        r = analyze_password("TestPass1!")
        assert r["level_label"] == mapping[r["level"]]
