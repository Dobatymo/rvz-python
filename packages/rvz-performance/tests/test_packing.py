import unittest

from rvz_performance import generate_padding_cached_numpy, generate_padding_cffi, generate_padding_numpy

EXPECTED = bytes.fromhex("1d757e0b64346456b7f95f37b14dcdec2ea34b4f13ef95cae6a79d4f23ca1813")


class PerformancePaddingTests(unittest.TestCase):
    def test_numpy_matches_known_vector(self) -> None:
        seed = bytes(range(68))
        self.assertEqual(generate_padding_numpy(seed, len(EXPECTED)), EXPECTED)
        self.assertEqual(generate_padding_cached_numpy(seed, len(EXPECTED)), EXPECTED)

    def test_cffi_matches_known_vector(self) -> None:
        self.assertEqual(generate_padding_cffi(bytes(range(68)), len(EXPECTED)), EXPECTED)


if __name__ == "__main__":
    unittest.main()
