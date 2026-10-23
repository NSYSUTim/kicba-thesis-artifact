"""Evidence extraction must preserve existing bytes and stay in its directory."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_research_updates as verification


class EvidenceExtractionTests(unittest.TestCase):
    def temporary(self):
        repository = Path(__file__).resolve().parents[1]
        base = repository / "reproduced"
        base.resolve().relative_to(repository.resolve())
        base.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base, prefix="verification-test-")
        Path(temporary.name).resolve().relative_to(base.resolve())
        return temporary

    def archive(self, root, member, data):
        archive = root / "test.tar"
        with tarfile.open(archive, "w") as bundle:
            info = tarfile.TarInfo(member)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
        return archive

    def test_conflicting_existing_evidence_is_never_overwritten(self):
        with self.temporary() as folder:
            root = Path(folder)
            target = root / "phase2/evidence/result.json"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"original evidence")
            archive = self.archive(root, "phase2/evidence/result.json", b"replacement")
            with patch.object(verification, "ROOT", root):
                with self.assertRaisesRegex(RuntimeError, "Conflicting retained evidence"):
                    verification.unpack_evidence(archive, "phase2")
            self.assertEqual(target.read_bytes(), b"original evidence")

    def test_parent_traversal_is_rejected_without_writing(self):
        with self.temporary() as folder:
            root = Path(folder)
            archive = self.archive(root, "phase2/evidence/../outside.txt", b"invalid")
            with patch.object(verification, "ROOT", root):
                with self.assertRaisesRegex(RuntimeError, "Unsafe archive member"):
                    verification.unpack_evidence(archive, "phase2")
            self.assertEqual(list(root.rglob("outside.txt")), [])

    def test_valid_evidence_can_be_extracted_and_rechecked(self):
        with self.temporary() as folder:
            root = Path(folder)
            archive = self.archive(root, "evidence/example/result.json", b"retained")
            with patch.object(verification, "ROOT", root):
                verification.unpack_evidence(archive, "phase1")
                verification.unpack_evidence(archive, "phase1")
            self.assertEqual((root / "phase1/evidence/example/result.json").read_bytes(), b"retained")


if __name__ == "__main__":
    unittest.main()
