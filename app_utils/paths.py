from __future__ import annotations

import os
import shutil
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

APP_NAME = "Zenvor Lock"
APP_DISPLAY_NAME = "Zenvor Lock"
FALLBACK_RUNTIME_DIR_NAME = ".runtime"


def get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _candidate_legacy_roots() -> list[Path]:
    roots = [Path.cwd(), get_project_root()]

    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)

    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        roots.append(Path(local_appdata) / "SecureAppLocker")

    unique_roots: list[Path] = []
    seen: set[Path] = set()

    for root in roots:
        resolved = root.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_roots.append(resolved)

    return unique_roots


def _deduplicate_paths(paths: list[Path]) -> list[Path]:
    unique_paths: list[Path] = []
    seen: set[Path] = set()

    for path in paths:
        resolved = _resolve_path(path)
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_paths.append(resolved)

    return unique_paths


def _build_fallback_data_dir_candidates() -> list[Path]:
    return _deduplicate_paths(
        [
            Path.cwd() / FALLBACK_RUNTIME_DIR_NAME,
            get_project_root() / FALLBACK_RUNTIME_DIR_NAME,
            Path(tempfile.gettempdir()) / APP_NAME,
        ]
    )


def _is_writable_directory(path: Path) -> bool:
    probe_path = _resolve_path(path) / ".secureapp-write-test"
    try:
        probe_path.parent.mkdir(parents=True, exist_ok=True)
        with open(probe_path, "a", encoding="utf-8"):
            pass
    except OSError:
        return False
    finally:
        try:
            probe_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    return True


def _get_primary_data_dir() -> Path:
    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / APP_NAME

    return get_project_root() / ".data"


@lru_cache(maxsize=1)
def get_data_dir() -> Path:
    candidates = _deduplicate_paths(
        [_get_primary_data_dir(), *_build_fallback_data_dir_candidates()]
    )

    for data_dir in candidates:
        if _is_writable_directory(data_dir):
            data_dir.mkdir(parents=True, exist_ok=True)
            return data_dir

    candidate_list = ", ".join(str(path) for path in candidates)
    raise PermissionError(f"Unable to create a writable runtime directory. Tried: {candidate_list}")


def _candidate_data_roots() -> list[Path]:
    return _deduplicate_paths([_get_primary_data_dir(), *_candidate_legacy_roots()])


def _migrate_legacy_file(filename: str, target: Path, legacy_subdir: str | None = None) -> None:
    if target.exists():
        return

    for root in _candidate_data_roots():
        source_dir = root / legacy_subdir if legacy_subdir else root
        source = source_dir / filename
        if not source.exists():
            continue
        if _resolve_path(source) == _resolve_path(target):
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        break


def get_database_path() -> Path:
    db_path = get_data_dir() / "secureapp.db"
    _migrate_legacy_file("secureapp.db", db_path)
    return db_path


def get_log_file_path() -> Path:
    log_path = get_data_dir() / "logs" / "secureapp.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    _migrate_legacy_file("secureapp.log", log_path, legacy_subdir="logs")
    return log_path
