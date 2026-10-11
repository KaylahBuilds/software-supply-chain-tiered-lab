"""Offline mutations: local consistency checks are not an authenticity oracle."""

from dataclasses import FrozenInstanceError
from io import BytesIO
import json
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from lab.build import build
from lab.common import (ARTIFACT_NAME, DEFAULT_FIXTURES, LabError, MAX_COMPONENT_BYTES,
                        OUTPUT_NAMES, RECORD_NAME, SBOM_NAME, ZIP_DATE, ZIP_PERMISSIONS,
                        digest, json_bytes, validate_inputs, zip_bytes)
from lab.verify import verify


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        # Keep generated data in this owned test directory. Some restricted
        # Windows environments cannot create descendants under their default
        # AppContainer temp path. TemporaryDirectory removes only its own child.
        self.temporary = tempfile.TemporaryDirectory(
            prefix="supply-chain-lab-", dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixtures = self.root / "fixtures"
        shutil.copytree(DEFAULT_FIXTURES, self.fixtures)
        self.lock = self.fixtures / "components.lock.json"
        self.component = self.fixtures / "components/greeting.py"
        self.output = self.root / "artifacts"

    def change_lock(self, callback):
        manifest = json.loads(self.lock.read_text(encoding="utf-8"))
        callback(manifest)
        self.lock.write_bytes(json_bytes(manifest))

    def change_record(self, callback):
        path = self.output / RECORD_NAME
        record = json.loads(path.read_text(encoding="utf-8"))
        callback(record)
        path.write_bytes(json_bytes(record))

    def make_build(self):
        return build(self.output, fixtures=self.fixtures)

    def test_valid_pinned_fixture_builds_exact_output_set(self):
        record = self.make_build()
        self.assertEqual({path.name for path in self.output.iterdir()}, OUTPUT_NAMES)
        self.assertFalse(record["signed"])
        self.assertIn("NOT trusted provenance", record["trust_notice"])

    def test_same_inputs_produce_identical_zip_sbom_and_record_bytes(self):
        self.make_build()
        second = self.root / "rebuilt"
        build(second, fixtures=self.fixtures)
        for name in OUTPUT_NAMES:
            with self.subTest(name=name):
                self.assertEqual((self.output / name).read_bytes(), (second / name).read_bytes())

    def test_zip_metadata_is_fixed_and_paths_are_narrow(self):
        self.make_build()
        with zipfile.ZipFile(self.output / ARTIFACT_NAME) as archive:
            self.assertEqual(archive.namelist(), ["components/greeting.py"])
            info = archive.infolist()[0]
            self.assertEqual(info.date_time, ZIP_DATE)
            self.assertEqual(info.external_attr, ZIP_PERMISSIONS)
            self.assertEqual(info.create_system, 3)
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED)

    def test_sbom_declares_format_and_limited_inventory(self):
        self.make_build()
        bom = json.loads((self.output / SBOM_NAME).read_bytes())
        self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.6"))
        self.assertEqual(len(bom["components"]), 1)
        self.assertIn("NOT a complete OS", bom["metadata"]["properties"][0]["value"])
        self.assertEqual(bom["components"][0]["hashes"][0]["content"], digest(self.component.read_bytes()))

    def test_valid_verification_explicitly_does_not_authenticate(self):
        self.make_build()
        result = verify(self.output)
        self.assertTrue(result["consistent"])
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["signed"])

    def test_dependency_tampering_fails_before_any_output_is_created(self):
        self.component.write_bytes(self.component.read_bytes() + b"\n# changed\n")
        with self.assertRaises(LabError):
            self.make_build()
        self.assertFalse(self.output.exists())

    def test_mutable_version_label_is_not_a_content_pin(self):
        self.change_lock(lambda manifest: manifest["components"][0].update(version="latest"))
        with self.assertRaises(LabError):
            self.make_build()

    def test_missing_and_extra_input_files_are_rejected(self):
        original = self.component.read_bytes()
        self.component.unlink()
        with self.assertRaises(LabError):
            validate_inputs(self.fixtures)
        self.component.write_bytes(original)
        (self.fixtures / "components/unlocked.py").write_text("# synthetic extra\n", encoding="utf-8")
        with self.assertRaises(LabError):
            validate_inputs(self.fixtures)

    def test_path_traversal_absolute_and_noncanonical_names_are_rejected(self):
        original = self.lock.read_bytes()
        for path in ("../outside.py", "/etc/passwd", "C:/secret", "a\\b", "a/../b", "a//b", "./greeting.py"):
            with self.subTest(path=path):
                self.lock.write_bytes(original)
                self.change_lock(lambda manifest: manifest["components"][0].update(path=path))
                with self.assertRaises(LabError):
                    validate_inputs(self.fixtures)

    def test_duplicate_component_metadata_is_rejected(self):
        self.change_lock(lambda manifest: manifest["components"].append(dict(manifest["components"][0])))
        with self.assertRaises(LabError):
            validate_inputs(self.fixtures)

    def test_missing_malformed_and_duplicate_key_lock_metadata_is_rejected(self):
        for payload in (b"not json", b"{}", b'{"schema":"a","schema":"b","components":[]}'):
            with self.subTest(payload=payload):
                self.lock.write_bytes(payload)
                with self.assertRaises(LabError):
                    validate_inputs(self.fixtures)

    def test_malformed_content_pins_are_rejected(self):
        original = self.lock.read_bytes()
        for content_hash in (None, "abc", "0" * 63, "A" * 64):
            with self.subTest(content_hash=content_hash):
                self.lock.write_bytes(original)
                self.change_lock(lambda manifest: manifest["components"][0].update(sha256=content_hash))
                with self.assertRaises(LabError):
                    validate_inputs(self.fixtures)

    def test_symlink_and_reparse_metadata_is_rejected_without_following_it(self):
        # Simulated lstat metadata works without enabling Windows symlink privileges.
        real_lstat = Path.lstat
        for mode, attributes in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o644, 0x400)):
            def fake_lstat(path):
                if path == self.component:
                    return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                return real_lstat(path)
            with self.subTest(mode=mode, attributes=attributes), patch.object(Path, "lstat", fake_lstat):
                with self.assertRaises(LabError):
                    validate_inputs(self.fixtures)

    def test_component_size_limit_is_enforced_even_with_an_updated_pin(self):
        content = b"x" * (MAX_COMPONENT_BYTES + 1)
        self.component.write_bytes(content)
        self.change_lock(lambda manifest: manifest["components"][0].update(sha256=digest(content)))
        with self.assertRaises(LabError):
            validate_inputs(self.fixtures)

    def test_snapshot_is_immutable_and_never_reopens_changed_input(self):
        approved = validate_inputs(self.fixtures)
        original = approved[0].content
        self.component.write_bytes(b"# mutation after validation\n")
        with self.assertRaises(FrozenInstanceError):
            approved[0].content = b"replacement"
        with zipfile.ZipFile(BytesIO(zip_bytes(approved))) as archive:
            self.assertEqual(archive.read("components/greeting.py"), original)
        with self.assertRaises(LabError):
            validate_inputs(self.fixtures)

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_bytes(b"preserve existing user content")
        with self.assertRaises(LabError):
            self.make_build()
        self.assertEqual(sentinel.read_bytes(), b"preserve existing user content")
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_outputs_cannot_be_written_into_fixture_inputs(self):
        with self.assertRaises(LabError):
            build(self.fixtures / "generated", fixtures=self.fixtures)
        self.assertFalse((self.fixtures / "generated").exists())

    def test_output_dotdot_alias_cannot_bypass_fixture_boundary(self):
        (self.root / "other").mkdir()
        alias = self.root / "other/../fixtures/generated"
        with self.assertRaises(LabError):
            build(alias, fixtures=self.fixtures)
        self.assertFalse((self.fixtures / "generated").exists())

    def test_output_parent_symlink_metadata_is_rejected(self):
        parent = self.root / "linked-parent"
        parent.mkdir()
        real_lstat = Path.lstat

        def fake_lstat(path):
            if path == parent:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0)
            return real_lstat(path)

        with patch.object(Path, "lstat", fake_lstat), self.assertRaises(LabError):
            build(parent / "artifacts", fixtures=self.fixtures)
        self.assertFalse((parent / "artifacts").exists())

    def test_missing_and_extra_outputs_fail_verification(self):
        self.make_build()
        record = (self.output / RECORD_NAME).read_bytes()
        (self.output / RECORD_NAME).unlink()
        with self.assertRaises(LabError):
            verify(self.output)
        (self.output / RECORD_NAME).write_bytes(record)
        (self.output / "unexpected.txt").write_bytes(b"extra")
        with self.assertRaises(LabError):
            verify(self.output)

    def test_wrong_artifact_and_traversal_members_fail_verification(self):
        self.make_build()
        (self.output / ARTIFACT_NAME).write_bytes(b"not a zip")
        with self.assertRaises(LabError):
            verify(self.output)
        with zipfile.ZipFile(self.output / ARTIFACT_NAME, "w") as archive:
            archive.writestr("../outside.py", "# synthetic\n")
        with self.assertRaises(LabError):
            verify(self.output)

    def test_missing_malformed_and_false_signing_record_metadata_is_rejected(self):
        self.make_build()
        record_path = self.output / RECORD_NAME
        original = record_path.read_bytes()
        for payload in (b"not json", b"{}", b'{"signed":false,"signed":true}'):
            with self.subTest(payload=payload):
                record_path.write_bytes(payload)
                with self.assertRaises(LabError):
                    verify(self.output)
        record_path.write_bytes(original)
        self.change_record(lambda record: record.update(signed=True))
        with self.assertRaises(LabError):
            verify(self.output)

    def test_wrong_record_hashes_sizes_and_path_names_are_rejected(self):
        self.make_build()
        original = (self.output / RECORD_NAME).read_bytes()
        mutations = [
            lambda record: record["artifact"].update(sha256="0" * 64),
            lambda record: record["artifact"].update(name="../outside.zip"),
            lambda record: record["artifact"].update(size_bytes=float(record["artifact"]["size_bytes"])),
            lambda record: record["sbom"].update(size_bytes=True),
            lambda record: record.update(lock_sha256="0" * 64),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                (self.output / RECORD_NAME).write_bytes(original)
                self.change_record(mutation)
                with self.assertRaises(LabError):
                    verify(self.output)

    def test_wrong_or_incomplete_sbom_is_rejected(self):
        self.make_build()
        (self.output / SBOM_NAME).write_bytes(json_bytes({"bomFormat": "CycloneDX", "specVersion": "1.6"}))
        with self.assertRaises(LabError):
            verify(self.output)

    def test_a_rewritten_lock_and_record_can_be_consistent_not_authentic(self):
        content = self.component.read_bytes() + b"\n# synthetic reviewed change\n"
        self.component.write_bytes(content)
        self.change_lock(lambda manifest: manifest["components"][0].update(sha256=digest(content)))
        self.make_build()
        result = verify(self.output)
        self.assertTrue(result["consistent"])
        self.assertFalse(result["authenticated"])


if __name__ == "__main__":
    unittest.main()
