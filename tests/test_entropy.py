import unittest

import support
from leakpulse.entropy import candidates, looks_random, shannon_entropy


class EntropyTests(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0, places=6)
        self.assertAlmostEqual(shannon_entropy("0123456789abcdef"), 4.0, places=6)

    def test_random_secret_is_flagged(self):
        self.assertTrue(looks_random(support.fake_secret(40)))

    def test_low_entropy_is_ignored(self):
        self.assertFalse(looks_random("a" * 40))
        self.assertFalse(looks_random("abababababababababababababababababababab"))

    def test_identifiers_and_uuids_are_ignored(self):
        self.assertFalse(looks_random("this_is_a_really_long_lowercase_identifier_name"))
        self.assertFalse(looks_random("123e4567-e89b-12d3-a456-426614174000"))

    def test_placeholders_are_ignored(self):
        self.assertFalse(looks_random("example_token_1234567890abcdef"))

    def test_threshold_is_respected(self):
        value = support.fake_secret(40)
        self.assertFalse(looks_random(value, threshold=9.0))

    def test_candidates_are_deduplicated(self):
        value = support.fake_secret(40)
        found = candidates(f'key = "{value}"')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][2], value)


if __name__ == "__main__":
    unittest.main()
