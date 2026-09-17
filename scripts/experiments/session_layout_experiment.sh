#!/usr/bin/env bash
# Prepare or restore the disposable-state session-layout experiment.
#
# This script deliberately never starts Codex.  Run `prepare`, inspect the
# session in the Codex UI, close Codex, then run `restore`.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  session_layout_experiment.sh prepare --config FILE --source FILE --relative-path PATH --backup-dir DIR
  session_layout_experiment.sh restore --config FILE --backup DIR

prepare validates the configured state is cold, creates a full backup outside
.codex, then copies FILE to the supplied session-relative PATH.  PATH must be
under sessions/ or archived_sessions/ and end in .jsonl.

After prepare, open Codex yourself and observe whether the session appears.
Close Codex before running restore.
EOF
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

require_value() {
  [[ $# -ge 2 ]] || fail "Missing value for $1"
}

resolve_dir() {
  local path=$1
  [[ -d $path ]] || fail "Directory does not exist: $path"
  realpath -- "$path"
}

resolve_file() {
  local path=$1
  [[ -f $path && ! -L $path ]] || fail "Regular source file does not exist: $path"
  realpath -- "$path"
}

assert_outside() {
  local child=$1 parent=$2 label=$3
  [[ $child != "$parent" && $child != "$parent"/* ]] || fail "$label must be outside the Codex state directory"
}

parse_common() {
  config=""
  source=""
  relative_path=""
  backup_dir=""
  backup=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --config) require_value "$@"; config=$2; shift 2 ;;
      --source) require_value "$@"; source=$2; shift 2 ;;
      --relative-path) require_value "$@"; relative_path=$2; shift 2 ;;
      --backup-dir) require_value "$@"; backup_dir=$2; shift 2 ;;
      --backup) require_value "$@"; backup=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown argument: $1" ;;
    esac
  done
  [[ -n $config ]] || fail "--config is required"
  [[ -f $config ]] || fail "Config file does not exist: $config"
}

state_dir_from_config() {
  python - "$config" <<'PY'
from pathlib import Path
import sys

from codexsync.config import load_config
from codexsync.state_locator import detect_local_state_dir

cfg = load_config(Path(sys.argv[1]))
print(detect_local_state_dir(cfg.paths.local_state_dir).resolve())
PY
}

prepare() {
  [[ -n $source && -n $relative_path && -n $backup_dir ]] || fail "prepare needs --source, --relative-path and --backup-dir"
  [[ $relative_path != /* && $relative_path != *".."* ]] || fail "--relative-path must not be absolute or contain .."
  [[ $relative_path == sessions/*.jsonl || $relative_path == archived_sessions/*.jsonl ]] || fail "--relative-path must be a .jsonl path under sessions/ or archived_sessions/"

  local source_file state_dir backup_root destination timestamp
  source_file=$(resolve_file "$source")
  state_dir=$(state_dir_from_config)
  backup_root=$(resolve_dir "$backup_dir")
  assert_outside "$backup_root" "$state_dir" "--backup-dir"
  assert_outside "$source_file" "$state_dir" "--source"

  # The preflight is the process safety authority. It refuses when Codex is
  # running or process state cannot be proven stopped.
  python -m codexsync -c "$config" preflight --for sync
  python -m codexsync -c "$config" guardian snapshot --once

  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  backup="$backup_root/codex-state-before-layout-experiment-$timestamp"
  [[ ! -e $backup ]] || fail "Generated backup path already exists: $backup"
  cp -a -- "$state_dir" "$backup"

  destination="$state_dir/$relative_path"
  [[ ! -e $destination ]] || fail "Destination already exists; choose a session absent from this state: $destination"
  mkdir -p -- "$(dirname -- "$destination")"
  cp -- "$source_file" "$destination"

  printf 'Experiment prepared. Backup: %s\n' "$backup"
  printf 'Copied session to: %s\n' "$destination"
  printf '\nNow open Codex manually and check whether the session appears.\n'
  printf 'Close Codex completely, then restore with:\n'
  printf '  %q restore --config %q --backup %q\n' "$0" "$config" "$backup"
}

restore() {
  [[ -n $backup ]] || fail "restore needs --backup"
  local state_dir backup_path
  state_dir=$(state_dir_from_config)
  backup_path=$(resolve_dir "$backup")
  assert_outside "$backup_path" "$state_dir" "--backup"
  python -m codexsync -c "$config" preflight --for sync

  # Replacing a state directory is intentionally not automated. The backup
  # remains intact and the user must make the final restore choice explicitly.
  printf 'Codex is stopped and this backup is ready to restore:\n  %s\n' "$backup_path"
  printf 'Restore it manually only after confirming the experiment result.\n'
  printf 'This script never deletes or replaces .codex.\n'
}

[[ $# -ge 1 ]] || { usage; exit 2; }
mode=$1
shift
if [[ $mode == -h || $mode == --help ]]; then
  usage
  exit 0
fi
parse_common "$@"
case $mode in
  prepare) prepare ;;
  restore) restore ;;
  *) fail "Unknown mode: $mode" ;;
esac
