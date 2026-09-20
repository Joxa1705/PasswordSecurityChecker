import unittest

from security_core import (
    generate_password,
    is_common_password,
    detect_weak_pattern,
    calculate_entropy,
    get_risk_level,
    calculate_security_health,
    analyze_password,
)


class TestSecurityCore(unittest.TestCase):

    # ---------------------------------------------------------
    # Password Generation
    # ---------------------------------------------------------

    def test_generate_password(self):
        password = generate_password(16)

        self.assertIsInstance(password, str)
        self.assertEqual(len(password), 16)

    def test_generate_password_different_lengths(self):
        password = generate_password(20)

        self.assertIsInstance(password, str)
        self.assertEqual(len(password), 20)

    # ---------------------------------------------------------
    # Common Password Detection
    # ---------------------------------------------------------

    def test_common_password_detection(self):
        result = is_common_password("password")

        self.assertTrue(result)

    def test_non_common_password_detection(self):
        result = is_common_password("X7mQ9pL2zR8!K4")

        self.assertFalse(result)

    # ---------------------------------------------------------
    # Weak Pattern Detection
    # ---------------------------------------------------------

    def test_keyboard_pattern_detection(self):
        result = detect_weak_pattern("qwerty123")

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_sequential_number_detection(self):
        result = detect_weak_pattern("abc12345")

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_repeated_character_detection(self):
        result = detect_weak_pattern("aaaa1234")

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_year_detection(self):
        result = detect_weak_pattern("Javohir2008!")

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    # ---------------------------------------------------------
    # Entropy
    # ---------------------------------------------------------

    def test_entropy_calculation(self):
        entropy = calculate_entropy("Abc123!@#")

        self.assertIsInstance(entropy, (int, float))
        self.assertGreater(entropy, 0)

    # ---------------------------------------------------------
    # Risk Level
    # ---------------------------------------------------------

    def test_risk_level_exists(self):
        risk = get_risk_level(
            80,
            False,
            False,
            0
        )

        self.assertIsInstance(risk, str)
        self.assertGreater(len(risk), 0)

    # ---------------------------------------------------------
    # Security Health
    # ---------------------------------------------------------

    def test_security_health_exists(self):
        result = analyze_password("StrongPassword123!")

        health = calculate_security_health(result)

        self.assertIsInstance(health, (int, float))
        self.assertGreaterEqual(health, 0)
        self.assertLessEqual(health, 100)

    # ---------------------------------------------------------
    # Complete Password Analysis
    # ---------------------------------------------------------

    def test_password_analysis(self):
        result = analyze_password("StrongPassword123!")

        self.assertIsInstance(result, dict)

    def test_password_analysis_contains_score(self):
        result = analyze_password("StrongPassword123!")

        self.assertIn("score", result)

    # ---------------------------------------------------------
    # Test Runner
    # ---------------------------------------------------------


if __name__ == "__main__":
    unittest.main()