from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from prepare_d7_canonical_view import EXPECTED_BOOTS, prepare_view


class D7CanonicalViewTests(unittest.TestCase):
    def _source(self, root: Path) -> Path:
        source = root / "raw"
        source.mkdir()
        for index, boot in enumerate(EXPECTED_BOOTS, start=1):
            formal = source / boot
            formal.mkdir()
            (formal / "batch.json").write_bytes(f"formal-{index}".encode())
            fixture = source / f"{boot}_fixture"
            fixture.mkdir()
            (fixture / "visible").write_text("fixture", encoding="utf-8")
        return source

    def test_exact_boots_are_copied_and_fixtures_are_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            output = root / "canonical"
            manifest = root / "manifest.json"
            report = prepare_view(source, output, manifest)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                list(EXPECTED_BOOTS),
            )
            self.assertFalse(any(output.glob("*_fixture")))
            saved = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(saved["included_directories"], list(EXPECTED_BOOTS))
            for boot in EXPECTED_BOOTS:
                self.assertEqual(
                    (source / boot / "batch.json").read_bytes(),
                    (output / boot / "batch.json").read_bytes(),
                )

    def test_unexpected_boot_like_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            (source / "boot_09_partial").mkdir()
            with self.assertRaisesRegex(RuntimeError, "unexpected boot-like"):
                prepare_view(source, root / "canonical", root / "manifest.json")

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._source(root)
            output = root / "canonical"
            output.mkdir()
            with self.assertRaises(FileExistsError):
                prepare_view(source, output, root / "manifest.json")


if __name__ == "__main__":
    unittest.main()
