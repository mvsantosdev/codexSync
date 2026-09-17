from __future__ import annotations

import json
from pathlib import Path
import shutil
import unittest
import uuid
from unittest.mock import patch

from codexsync.app import create_portable_snapshot
from codexsync.exceptions import FailSafeError
from codexsync.guardian_models import SourceObservation, ValidationReport, ValidationStatus
from codexsync.guardian_store import GuardianStore
from codexsync.portable_snapshot import build_portable_snapshot, validate_portable_snapshot
from codexsync.safety_gate import ProcessState


class PortableSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("/tmp") / f"codexsync-portable-{uuid.uuid4()}"
        self.source = self.root / "state"
        self.source.mkdir(parents=True)
        (self.source / "sessions").mkdir()
        (self.source / "sessions" / "one.jsonl").write_text('{"type":"session"}\n', encoding="utf-8")
        (self.source / "state.sqlite").write_bytes(b"sqlite")
        (self.source / "auth.json").write_text("secret", encoding="utf-8")
        (self.source / "cache").mkdir()
        (self.source / "cache" / "skip").write_text("no", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_builds_and_verifies_only_portable_files(self) -> None:
        snapshot = build_portable_snapshot(self.source, self.root / "snapshot", target_machine_id="laptop")
        self.assertEqual({item.relative_path for item in snapshot.entries}, {"sessions/one.jsonl", "state.sqlite"})
        self.assertEqual(validate_portable_snapshot(self.root / "snapshot"), snapshot)
        self.assertFalse((self.root / "snapshot" / "auth.json").exists())

    def test_validation_rejects_unmanifested_or_unsafe_content(self) -> None:
        destination = self.root / "snapshot"
        build_portable_snapshot(self.source, destination, target_machine_id="laptop")
        (destination / "unexpected.txt").write_text("no", encoding="utf-8")
        with self.assertRaises(FailSafeError):
            validate_portable_snapshot(destination)
        (destination / "unexpected.txt").unlink()
        manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        manifest["entries"][0]["relative_path"] = "../escape"
        (destination / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(FailSafeError):
            validate_portable_snapshot(destination)

    def test_refuses_a_staging_directory_inside_state(self) -> None:
        with self.assertRaises(FailSafeError):
            build_portable_snapshot(self.source, self.source / "snapshot", target_machine_id="laptop")

    def test_can_include_a_verified_guardian_snapshot(self) -> None:
        guardian = GuardianStore(self.root / "guardian", "desktop", producer_version="test")
        payload = b'{"local-projects":{},"project-order":[],"thread-project-assignments":{}}'
        outcome = guardian.commit(
            SourceObservation(
                payload, ".codex-global-state.json", len(payload), len(payload), 1, 1, None, None, True,
            ),
            ValidationReport(ValidationStatus.PASS, project_count=0, binding_count=0),
        )
        assert outcome.snapshot is not None
        snapshot = build_portable_snapshot(
            self.source, self.root / "snapshot", target_machine_id="laptop", guardian_snapshot=outcome.snapshot,
        )
        self.assertIn("guardian/.codex-global-state.json", {entry.relative_path for entry in snapshot.entries})
        self.assertEqual(validate_portable_snapshot(self.root / "snapshot"), snapshot)

    def test_app_refuses_an_existing_dangling_output_link(self) -> None:
        output = self.root / "published"
        output.symlink_to(self.root / "missing-target")
        config = self.root / "config.toml"
        config.write_text(
            "\n".join((
                "[identity]", 'machine_id = "test-machine"',
                "[paths]", f'local_state_dir = "{self.source}"',
                f'cloud_root_dir = "{self.root / "cloud"}"',
                f'backup_dir = "{self.root / "backups"}"',
                f'temp_dir = "{self.root / "temp"}"',
            )), encoding="utf-8",
        )
        with self.assertRaisesRegex(Exception, "already exists"):
            create_portable_snapshot(config, output=output, target_machine_id="laptop")

    def test_app_publishes_only_after_cold_safety_check(self) -> None:
        config = self.root / "config.toml"
        config.write_text(
            "\n".join((
                "[identity]", 'machine_id = "test-machine"',
                "[paths]", f'local_state_dir = "{self.source}"',
                f'cloud_root_dir = "{self.root / "cloud"}"',
                f'backup_dir = "{self.root / "backups"}"',
                f'temp_dir = "{self.root / "temp"}"',
            )), encoding="utf-8",
        )
        with patch("codexsync.runtime.CodexProcessDetector") as detector:
            detector.return_value.list_running.return_value = []
            detector.return_value.find_processes.return_value = []
            detector.return_value.get_subprocess_tree.return_value = ([], [])
            detector.return_value.has_subprocess_marker.return_value = False
            detector.return_value.capability.return_value.supported = True
            detector.return_value.capability.return_value.platform = "linux"
            snapshot = create_portable_snapshot(
                config, output=self.root / "published", target_machine_id="laptop",
            )
        self.assertEqual(len(snapshot.entries), 2)
        self.assertEqual(snapshot.target_machine_id, "laptop")
        self.assertTrue((self.root / "published" / "manifest.json").is_file())
