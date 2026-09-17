from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import unittest

from codexsync.process_detector import CodexProcessDetector, ProcessInfo


class _Result:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout


class ProcessDetectorTests(unittest.TestCase):
    @patch("codexsync.process_detector.sys.platform", "win32")
    @patch("codexsync.process_detector.subprocess.run")
    def test_windows_matches_name_without_exe_suffix(self, run_mock) -> None:
        run_mock.side_effect = [
            _Result(returncode=0, stdout='"CODEX-WINDOWS-SANDBOX.EXE","4242","Console","1","10,000 K"\n'),
            _Result(returncode=0, stdout="[]"),
        ]
        detector = CodexProcessDetector(["codex-windows-sandbox"])
        running = detector.list_running()
        self.assertEqual(len(running), 1)
        self.assertEqual(running[0].pid, 4242)
        self.assertEqual(running[0].name, "CODEX-WINDOWS-SANDBOX.EXE")

    @patch("codexsync.process_detector.sys.platform", "win32")
    @patch("codexsync.process_detector.subprocess.run")
    def test_windows_subprocess_marker_in_codex_tree(self, run_mock) -> None:
        run_mock.side_effect = [
            _Result(returncode=0, stdout=""),
            _Result(
                returncode=0,
                stdout=(
                    '[{"ProcessId":1000,"ParentProcessId":10,"Name":"Codex.exe"},'
                    '{"ProcessId":1001,"ParentProcessId":1000,"Name":"codex-windows-sandbox.exe"}]'
                ),
            ),
        ]
        detector = CodexProcessDetector(["codex.exe"])
        present = detector.has_subprocess_marker(["codex.exe"], "codex-windows-sandbox")
        self.assertTrue(present)

    @patch("codexsync.process_detector.sys.platform", "win32")
    @patch("codexsync.process_detector.subprocess.run")
    def test_windows_does_not_match_unrelated_process_by_name(self, run_mock) -> None:
        run_mock.side_effect = [
            _Result(returncode=0, stdout='"python.exe","9999","Console","1","10,000 K"\n'),
            _Result(returncode=0, stdout='[{"ProcessId":9999,"Name":"python.exe"}]'),
        ]
        detector = CodexProcessDetector(["codex.exe"])
        running = detector.list_running()
        self.assertEqual(running, [])

    @patch("codexsync.process_detector.sys.platform", "linux")
    def test_linux_capability_and_executable_match(self) -> None:
        detector = CodexProcessDetector(["codex"])
        with patch.object(
            detector,
            "_list_linux_all",
            return_value=[ProcessInfo(100, "node", "", 1, "codex")],
        ):
            self.assertTrue(detector.capability().supported)
            self.assertEqual([item.pid for item in detector.list_running()], [100])

    @patch("codexsync.process_detector.sys.platform", "linux")
    def test_linux_no_codex_match_is_stopped_candidate(self) -> None:
        detector = CodexProcessDetector(["codex"])
        with patch.object(detector, "_list_linux_all", return_value=[ProcessInfo(100, "python", "python", 1)]):
            self.assertEqual(detector.list_running(), [])

    @patch("codexsync.process_detector.sys.platform", "linux")
    def test_linux_open_state_file_marker_counts_as_running(self) -> None:
        detector = CodexProcessDetector(["codex"])
        with patch.object(
            detector, "_list_linux_all", return_value=[ProcessInfo(-100, "codex-state-open", "", 1)]
        ):
            self.assertEqual([item.pid for item in detector.list_running()], [-100])

    @patch("codexsync.process_detector.sys.platform", "linux")
    def test_linux_process_tree_includes_vscode_child(self) -> None:
        detector = CodexProcessDetector(["codex"])
        processes = [
            ProcessInfo(100, "codex", "/usr/local/bin/codex", 1),
            ProcessInfo(101, "node", "/usr/bin/node\0extension.js", 100),
        ]
        with patch.object(detector, "_list_linux_all", return_value=processes):
            roots, children = detector.get_subprocess_tree(["codex"])
        self.assertEqual([item.pid for item in roots], [100])
        self.assertEqual([item.pid for item in children], [101])

    @patch("codexsync.process_detector.sys.platform", "linux")
    def test_linux_permission_denial_fails_closed(self) -> None:
        detector = CodexProcessDetector(["codex"])
        denied = Path("/proc/999999")
        with patch("codexsync.process_detector.Path.iterdir", return_value=[denied]), \
             patch.object(Path, "stat", side_effect=PermissionError("denied")), \
             patch("codexsync.process_detector.os.geteuid", return_value=0, create=True):
            with self.assertRaisesRegex(RuntimeError, "cannot inspect process"):
                detector._list_linux_all()


if __name__ == "__main__":
    unittest.main()
