import tempfile
import unittest
from pathlib import Path

import unchk_modern as unchk


class DetectionTests(unittest.TestCase):
    def test_whole_mode_matches_header_at_start(self):
        data = b"%PDF-1.7\nbody"
        matches = unchk.find_matches(data, "whole", unchk.default_signatures())
        self.assertTrue(any(match.extension == "pdf" and match.offset == 0 for match in matches))

    def test_harddisk_mode_finds_embedded_512_boundary(self):
        data = b"\0" * 512 + b"PK\x03\x04payload"
        matches = unchk.find_matches(data, "harddisk", unchk.default_signatures())
        self.assertTrue(any(match.extension == "zip" and match.offset == 512 for match in matches))

    def test_whole_mode_does_not_find_later_header(self):
        data = b"\0" * 512 + b"PK\x03\x04payload"
        matches = unchk.find_matches(data, "whole", unchk.default_signatures())
        self.assertFalse(any(match.extension == "zip" for match in matches))

    def test_riff_detector_identifies_wav(self):
        data = b"RIFF\x20\x00\x00\x00WAVEfmt "
        matches = unchk.find_matches(data, "whole", unchk.default_signatures())
        self.assertTrue(any(match.extension == "wav" and match.confidence == "high" for match in matches))

    def test_office_detector_identifies_word_marker(self):
        data = bytes.fromhex("D0CF11E0") + b"\0" * 128 + b"Microsoft Word"
        matches = unchk.find_matches(data, "whole", unchk.default_signatures())
        self.assertTrue(any(match.extension == "doc" for match in matches))

    def test_psd_detector_requires_plausible_header(self):
        valid = (
            b"8BPS"
            + (1).to_bytes(2, "big")
            + b"\0" * 6
            + (3).to_bytes(2, "big")
            + (100).to_bytes(4, "big")
            + (200).to_bytes(4, "big")
            + (8).to_bytes(2, "big")
            + (3).to_bytes(2, "big")
            + b"rest"
        )
        invalid = b"8BPS" + b"not-a-photoshop-header"
        valid_matches = unchk.find_matches(valid, "whole", unchk.default_signatures())
        invalid_matches = unchk.find_matches(invalid, "whole", unchk.default_signatures())
        self.assertTrue(any(match.extension == "psd" for match in valid_matches))
        self.assertFalse(any(match.extension == "psd" for match in invalid_matches))

    def test_text_detector_is_offset_zero_only(self):
        data = b"hello world\r\nthis is text\r\n"
        matches = unchk.find_matches(data, "whole", unchk.default_signatures())
        self.assertTrue(any(match.extension == "txt" for match in matches))

    def test_textual_code_detector_identifies_javascript(self):
        data = b"const name = 'demo';\nfunction run() {\n  console.log(name);\n}\n"
        matches = unchk.find_matches(data, "whole", unchk.default_signatures())
        self.assertTrue(any(match.extension == "js" for match in matches))


class ScanCommandTests(unittest.TestCase):
    def test_scan_copies_recovered_candidate_without_touching_source(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            source = base / "FOUND.000"
            out = base / "recovered"
            source.mkdir()
            chk = source / "FILE0001.CHK"
            original = b"%PDF-1.4\nexample"
            chk.write_bytes(original)

            rc = unchk.main(["scan", str(source), "--out", str(out), "--mode", "whole", "--write-log"])

            self.assertEqual(rc, 0)
            self.assertEqual(chk.read_bytes(), original)
            self.assertEqual((out / "FILE0001.pdf").read_bytes(), original)
            self.assertTrue((out / "unchk-modern.log").is_file())

    def test_carve_finds_target_signature_inside_file(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            source = base / "FOUND.000"
            out = base / "psd"
            source.mkdir()
            chk = source / "FILE0002.CHK"
            chk.write_bytes(b"prefix" + b"8BPS" + b"photoshop-data")

            rc = unchk.main(
                [
                    "carve",
                    str(source),
                    "--out",
                    str(out),
                    "--extension",
                    "psd",
                    "--header-hex",
                    "38425053",
                    "--write-log",
                ]
            )

            self.assertEqual(rc, 0)
            self.assertEqual((out / "FILE0002@00000006.psd").read_bytes(), b"8BPSphotoshop-data")


if __name__ == "__main__":
    unittest.main()
