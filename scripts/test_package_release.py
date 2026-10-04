"""Check release inventory boundaries without copying local build products."""
from pathlib import Path
import tempfile
import unittest

from package_release import public_files, digest


class PublicInventoryTests(unittest.TestCase):
    def test_only_public_trees_and_no_build_or_private_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            files = ('README.md', 'final/project/src/lib.rs', 'final/project/Cargo.lock',
                     'final/project/target/release/program', 'archive/results/run/EXPERIMENT.md',
                     'archive/local-artifacts/private-metadata/original.json',
                     '.git/config', 'output/public-repo/README.md', 'unrelated-local-file.txt')
            for relative in files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('sample')
            found = {str(path.relative_to(root)) for path in public_files(root)}
            self.assertEqual(found, {'README.md', 'final/project/src/lib.rs',
                                    'final/project/Cargo.lock', 'archive/results/run/EXPERIMENT.md'})

    def test_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'final').mkdir()
            (root / 'final/source').symlink_to('/does-not-exist')
            with self.assertRaises(ValueError):
                list(public_files(root))

    def test_streaming_digest(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'file'
            path.write_bytes(b'abc')
            self.assertEqual(digest(path), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')


if __name__ == '__main__':
    unittest.main()
