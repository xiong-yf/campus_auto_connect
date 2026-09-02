from __future__ import annotations

import unittest

from campus_connect.srun_crypto import encode_info, hmac_md5, sha1_hex, srun_base64, xencode


class SrunCryptoTests(unittest.TestCase):
    def test_base64_known_sample(self) -> None:
        # encrypt.py in common srun scripts prints get_base64("132456")
        self.assertEqual(srun_base64("132456"), "9F9x0JHI")

    def test_base64_padding(self) -> None:
        self.assertEqual(srun_base64("12"), "9F2=")
        self.assertEqual(srun_base64("123"), "9F2z")

    def test_hmac_and_sha1(self) -> None:
        # RFC 2202 HMAC-MD5 test: key="key", data=fox sentence
        self.assertEqual(
            hmac_md5("The quick brown fox jumps over the lazy dog", "key"),
            "80070713463e7749b90c2dc24911e275",
        )
        self.assertEqual(sha1_hex("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_xencode_not_empty(self) -> None:
        encoded = xencode('{"username":"u"}', "token")
        self.assertTrue(encoded)
        self.assertTrue(all(ord(ch) <= 255 for ch in encoded))

    def test_encode_info_prefix(self) -> None:
        info = encode_info('{"username":"u","password":"p","ip":"10.0.0.2","acid":"1","enc_ver":"srun_bx1"}', "tok")
        self.assertTrue(info.startswith("{SRBX1}"))
        self.assertGreater(len(info), 10)


if __name__ == "__main__":
    unittest.main()
