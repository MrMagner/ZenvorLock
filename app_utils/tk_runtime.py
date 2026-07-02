from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from app_utils.paths import get_project_root

_DLL_DIRECTORY_HANDLES = []
FORCE_BUNDLED_TK_ENV = "SECUREAPP_LOCKER_FORCE_BUNDLED_TK"
TK_RELAUNCH_ENV = "SECUREAPP_LOCKER_TK_RELAUNCHED"


def bootstrap_tk_runtime() -> None:
    if os.getenv(FORCE_BUNDLED_TK_ENV) == "1":
        bundled_layout = _bundled_runtime_layout()
        if bundled_layout is not None:
            tcl_dir, tk_dir, dll_dir = bundled_layout
            _apply_runtime_layout(tcl_dir, tk_dir, dll_dir)
            return

    if _has_valid_environment():
        return

    for tcl_dir, tk_dir, dll_dir in _candidate_runtime_layouts():
        if not _is_valid_runtime_layout(tcl_dir, tk_dir):
            continue

        _apply_runtime_layout(tcl_dir, tk_dir, dll_dir)
        return


def relaunch_with_compatible_python(script_path: str | Path, error: Exception | None = None) -> bool:
    if os.getenv(TK_RELAUNCH_ENV) == "1":
        return False

    if error is not None and "init.tcl" not in str(error):
        return False

    script = Path(script_path).resolve()
    env = os.environ.copy()
    env[TK_RELAUNCH_ENV] = "1"
    env[FORCE_BUNDLED_TK_ENV] = "1"

    for python_executable in _candidate_python_executables():
        try:
            subprocess.Popen(
                [str(python_executable), str(script), *sys.argv[1:]],
                cwd=str(script.parent),
                env=env,
            )
            return True
        except OSError:
            continue

    return False


def _has_valid_environment() -> bool:
    tcl_dir = Path(os.getenv("TCL_LIBRARY", ""))
    tk_dir = Path(os.getenv("TK_LIBRARY", ""))
    return _is_valid_runtime_layout(tcl_dir, tk_dir)


def _candidate_runtime_layouts() -> list[tuple[Path, Path, Path]]:
    project_root = get_project_root()
    bundled_internal = project_root / "dist" / "SecureAppLocker" / "_internal"

    return [
        (
            Path(sys.base_prefix) / "tcl" / "tcl8.6",
            Path(sys.base_prefix) / "tcl" / "tk8.6",
            Path(sys.base_prefix),
        ),
        (
            Path(sys.prefix) / "tcl" / "tcl8.6",
            Path(sys.prefix) / "tcl" / "tk8.6",
            Path(sys.prefix),
        ),
        (
            bundled_internal / "_tcl_data",
            bundled_internal / "_tk_data",
            bundled_internal,
        ),
    ]


def _bundled_runtime_layout() -> tuple[Path, Path, Path] | None:
    tcl_dir, tk_dir, dll_dir = _candidate_runtime_layouts()[-1]
    if not _is_valid_runtime_layout(tcl_dir, tk_dir):
        return None
    return tcl_dir, tk_dir, dll_dir


def _candidate_python_executables() -> list[Path]:
    project_root = get_project_root()
    current_python = Path(sys.executable).resolve(strict=False)
    candidates = [
        project_root / ".venv" / "Scripts" / "pythonw.exe",
        project_root / ".venv" / "Scripts" / "python.exe",
        project_root / "venv" / "Scripts" / "pythonw.exe",
        project_root / "venv" / "Scripts" / "python.exe",
    ]

    unique_candidates: list[Path] = []
    seen: set[Path] = set()

    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved == current_python or resolved in seen or not candidate.is_file():
            continue
        seen.add(resolved)
        unique_candidates.append(candidate)

    return unique_candidates


def _is_valid_runtime_layout(tcl_dir: Path, tk_dir: Path) -> bool:
    return (tcl_dir / "init.tcl").is_file() and (tk_dir / "tk.tcl").is_file()


def _apply_runtime_layout(tcl_dir: Path, tk_dir: Path, dll_dir: Path) -> None:
    os.environ["TCL_LIBRARY"] = str(tcl_dir)
    os.environ["TK_LIBRARY"] = str(tk_dir)
    _register_dll_directory(dll_dir)


def _register_dll_directory(dll_dir: Path) -> None:
    if not dll_dir.is_dir() or not hasattr(os, "add_dll_directory"):
        return

    try:
        handle = os.add_dll_directory(str(dll_dir))
    except OSError:
        return

    _DLL_DIRECTORY_HANDLES.append(handle)
