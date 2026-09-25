from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from prepare_d6_r2_formal_view import (
    FIXTURE_DIRS,
    FORMAL_BOOTS,
    build_formal_view,
)


class D6R2PostLockErratumTests(unittest.TestCase):
    def test_formal_view_excludes_fixtures_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "raw"
            output = root / "formal"
            source.mkdir()
            for index, name in enumerate(FORMAL_BOOTS, start=1):
                boot = source / name
                boot.mkdir()
                (boot / "campaign.json").write_bytes(
                    f"manifest-{index}".encode("ascii")
                )
            for name in FIXTURE_DIRS:
                fixture = source / name
                fixture.mkdir()
                (fixture / "visible-file").write_text("fixture", encoding="utf-8")

            report = build_formal_view(source, output)

            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                list(FORMAL_BOOTS),
            )
            self.assertEqual(report["file_count"], 5)
            for index, name in enumerate(FORMAL_BOOTS, start=1):
                self.assertEqual(
                    (output / name / "campaign.json").read_bytes(),
                    f"manifest-{index}".encode("ascii"),
                )

    def test_unexpected_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "raw"
            source.mkdir()
            for name in FORMAL_BOOTS + FIXTURE_DIRS:
                (source / name).mkdir()
            (source / "boot_extra").mkdir()
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                build_formal_view(source, root / "formal")


if __name__ == "__main__":
    unittest.main()
