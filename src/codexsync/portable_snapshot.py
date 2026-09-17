"""Cold, verifiable snapshots of the portable Codex state.

This module deliberately does not import the CLI or mutate a Codex state
directory.  It copies an explicitly selected state set into staging, verifies
that every source stayed stable, and emits a manifest.  Publishing/importing
the staged generation is a separate mutation-envelope concern.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil

from .exceptions import FailSafeError
from .guardian_models import GuardianSnapshot, require_guardian_machine_id
from .guardian_manifest import verify_guardian_snapshot


SNAPSHOT_FORMAT = "codexsync-portable-snapshot-v1"

# Credentials, liveness data and rebuildable machine-local material must never
# cross the handoff boundary.  SQLite is intentionally included as a complete
# set: the caller has already proved Codex stopped before this module runs.
_EXCLUDED_TOP_LEVEL = frozenset({"auth.json", "ipc", "thread-writer-locks", "cache", "logs"})
_INCLUDED_TOP_LEVEL = frozenset({"sessions", "archived_sessions", "session_index.jsonl", "plugins", "skills"})


@dataclass(frozen=True, slots=True)
class SnapshotEntry:
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class PortableSnapshot:
    entries: tuple[SnapshotEntry, ...]
    target_machine_id: str

    def manifest(self) -> dict[str, object]:
        return {
            "format": SNAPSHOT_FORMAT,
            "target_machine_id": self.target_machine_id,
            "entries": [asdict(entry) for entry in self.entries],
        }


def build_portable_snapshot(
    source: Path,
    staging: Path,
    *,
    target_machine_id: str,
    guardian_snapshot: GuardianSnapshot | None = None,
) -> PortableSnapshot:
    """Copy a stable, portable state set into an empty staging directory.

    A source which changes during the copy is refused.  The result stays
    outside `.codex`; callers can audit it before any publication or import.
    """
    source = source.resolve()
    staging = staging.resolve()
    target_machine_id = _require_machine_id(target_machine_id)
    if staging.exists():
        raise FailSafeError(f"Snapshot staging path already exists: {staging}")
    if not source.is_dir():
        raise FailSafeError(f"Codex state directory does not exist: {source}")
    if _overlaps(source, staging):
        raise FailSafeError("Snapshot staging path must be outside the Codex state directory")
    staging.mkdir(parents=True)
    entries: list[SnapshotEntry] = []
    try:
        expected = tuple(_portable_files(source))
        for path in expected:
            entries.append(_copy_verified(path, staging / path.relative_to(source), path.relative_to(source).as_posix()))
        if tuple(_portable_files(source)) != expected:
            raise FailSafeError("Codex state changed while snapshotting")
        if guardian_snapshot is not None:
            try:
                verify_guardian_snapshot(guardian_snapshot)
            except Exception as exc:
                raise FailSafeError("Requested Guardian snapshot does not verify") from exc
            for name in (".codex-global-state.json", "manifest.json", "COMMITTED"):
                path = guardian_snapshot.directory / name
                entries.append(_copy_verified(path, staging / "guardian" / name, f"guardian/{name}"))
        snapshot = PortableSnapshot(tuple(entries), target_machine_id)
        _write_manifest(staging / "manifest.json", snapshot)
        return snapshot
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def validate_portable_snapshot(root: Path) -> PortableSnapshot:
    """Validate a staged snapshot without consulting its original state."""
    try:
        raw = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        if raw.get("format") != SNAPSHOT_FORMAT or not isinstance(raw.get("entries"), list):
            raise ValueError("unsupported manifest")
        entries = tuple(SnapshotEntry(**entry) for entry in raw["entries"])
        target_machine_id = _require_machine_id(raw["target_machine_id"])
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise FailSafeError("Portable snapshot manifest is missing or invalid") from exc
    seen: set[str] = set()
    for entry in entries:
        _validate_entry(entry, seen)
        path = root / entry.relative_path
        if path.is_symlink() or not path.is_file() or path.stat().st_size != entry.size or _sha256(path) != entry.sha256:
            raise FailSafeError(f"Portable snapshot verification failed: {entry.relative_path}")
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != {"manifest.json", *seen}:
        raise FailSafeError("Portable snapshot contains files absent from its manifest")
    return PortableSnapshot(entries, target_machine_id)


def _portable_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        top = relative.parts[0]
        name = relative.name
        if top in _EXCLUDED_TOP_LEVEL:
            continue
        if top in _INCLUDED_TOP_LEVEL or name.endswith((".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal")):
            yield path


def _validate_entry(entry: SnapshotEntry, seen: set[str]) -> None:
    path = Path(entry.relative_path)
    if (
        not entry.relative_path
        or path.is_absolute()
        or ".." in path.parts
        or entry.relative_path in seen
        or entry.relative_path == "manifest.json"
        or not isinstance(entry.size, int)
        or entry.size < 0
        or not isinstance(entry.sha256, str)
        or len(entry.sha256) != 64
        or any(char not in "0123456789abcdef" for char in entry.sha256)
    ):
        raise FailSafeError("Portable snapshot manifest contains an invalid entry")
    seen.add(entry.relative_path)


def _copy_verified(source: Path, destination: Path, relative: str) -> SnapshotEntry:
    destination.parent.mkdir(parents=True, exist_ok=True)
    before = _signature(source)
    shutil.copy2(source, destination)
    source_hash = _sha256(source)
    copied_hash = _sha256(destination)
    after = _signature(source)
    if before != after or source_hash != copied_hash:
        raise FailSafeError(f"State changed while snapshotting: {relative}")
    return SnapshotEntry(relative, before[0], source_hash)


def _require_machine_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("target_machine_id must be a non-empty string")
    try:
        normalized = require_guardian_machine_id(value)
    except ValueError as exc:
        raise ValueError("target_machine_id must be a non-empty machine identity") from exc
    if normalized != value:
        raise ValueError("target_machine_id must be normalized")
    return normalized


def _overlaps(left: Path, right: Path) -> bool:
    try:
        right.relative_to(left)
        return True
    except ValueError:
        pass
    try:
        left.relative_to(right)
        return True
    except ValueError:
        return False


def _signature(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest(path: Path, snapshot: PortableSnapshot) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(snapshot.manifest(), handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
