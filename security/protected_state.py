from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # pragma: no cover - Windows-only runtime hardening
    winreg = None

from app_utils.paths import get_data_dir


CRYPTPROTECT_UI_FORBIDDEN = 0x01
PROTECTED_STATE_CONTEXT = b"SecureAppLocker.ProtectedState.v1"
REGISTRY_ROOT = r"Software\Zenvor Lock"
REGISTRY_INSTALL_ID_NAME = "InstallId"
REGISTRY_AUTH_CONFIGURED_NAME = "AuthConfigured"


class ProtectedStateError(RuntimeError):
    """Raised when the protected runtime state is missing or unreadable."""


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL
crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptUnprotectData.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL


def get_state_path() -> Path:
    return get_data_dir() / ".secureapp-auth.bin"


def get_guard_path() -> Path:
    return get_data_dir() / ".secureapp-install-guard.json"


def _build_default_state() -> dict[str, object]:
    return {
        "version": 1,
        "install_id": secrets.token_hex(16),
        "integrity_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "password_hash": "",
        "failed_attempts": 0,
        "lockout_until": 0.0,
        "created_at": time.time(),
        "updated_at": time.time(),
    }


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)


def _write_bytes_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_bytes(payload)
    temp_path.replace(path)


def _load_guard() -> dict[str, object] | None:
    guard_path = get_guard_path()
    if not guard_path.exists():
        return None

    try:
        payload = json.loads(guard_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtectedStateError("Install guard is unreadable.") from exc

    if not isinstance(payload, dict):
        raise ProtectedStateError("Install guard is invalid.")
    return payload


def _load_registry_anchor() -> dict[str, object] | None:
    if winreg is None:
        return None

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_ROOT) as key:
            install_id, _ = winreg.QueryValueEx(key, REGISTRY_INSTALL_ID_NAME)
            auth_configured, _ = winreg.QueryValueEx(key, REGISTRY_AUTH_CONFIGURED_NAME)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProtectedStateError("Install registry anchor is unreadable.") from exc

    return {
        "install_id": str(install_id or "").strip(),
        "auth_configured": bool(int(auth_configured or 0)),
    }


def _save_registry_anchor(state: dict[str, object], *, auth_configured: bool) -> None:
    if winreg is None:
        return

    try:
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            REGISTRY_ROOT,
            0,
            access=winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(
                key,
                REGISTRY_INSTALL_ID_NAME,
                0,
                winreg.REG_SZ,
                str(state.get("install_id") or ""),
            )
            winreg.SetValueEx(
                key,
                REGISTRY_AUTH_CONFIGURED_NAME,
                0,
                winreg.REG_DWORD,
                1 if auth_configured else 0,
            )
    except OSError as exc:
        raise ProtectedStateError(
            "Install registry anchor could not be updated."
        ) from exc


def _save_guard(state: dict[str, object], *, auth_configured: bool) -> None:
    payload = {
        "version": 1,
        "install_id": str(state.get("install_id") or ""),
        "auth_configured": bool(auth_configured),
        "updated_at": time.time(),
    }
    _write_json_atomic(get_guard_path(), payload)


def _anchor_requires_state(anchor: dict[str, Any] | None) -> bool:
    if not isinstance(anchor, dict):
        return False
    return bool(str(anchor.get("install_id") or "").strip()) or bool(
        anchor.get("auth_configured")
    )


def _validate_install_anchor(
    anchor: dict[str, Any] | None,
    *,
    state_install_id: str,
    password_hash: str,
    anchor_name: str,
) -> None:
    if not isinstance(anchor, dict):
        return

    anchor_install_id = str(anchor.get("install_id") or "").strip()
    if anchor_install_id and anchor_install_id != state_install_id:
        raise ProtectedStateError(
            f"Protected authentication state does not match the {anchor_name} installation anchor."
        )

    if bool(anchor.get("auth_configured")) and not password_hash:
        raise ProtectedStateError(
            f"Protected authentication state does not satisfy the {anchor_name} authentication anchor."
        )


def _bytes_to_blob(data: bytes) -> tuple[DATA_BLOB, ctypes.Array[ctypes.c_byte]]:
    if not data:
        return DATA_BLOB(0, None), (ctypes.c_byte * 1)()
    buffer = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    return DATA_BLOB(
        len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))
    ), buffer


def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    if not blob.cbData or not blob.pbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _protect_bytes(data: bytes) -> bytes:
    input_blob, _ = _bytes_to_blob(data)
    entropy_blob, _ = _bytes_to_blob(PROTECTED_STATE_CONTEXT)
    output_blob = DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        "SecureAppLocker state",
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError()

    try:
        return _blob_to_bytes(output_blob)
    finally:
        if output_blob.pbData:
            kernel32.LocalFree(output_blob.pbData)


def _unprotect_bytes(data: bytes) -> bytes:
    input_blob, _ = _bytes_to_blob(data)
    entropy_blob, _ = _bytes_to_blob(PROTECTED_STATE_CONTEXT)
    output_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError()

    try:
        return _blob_to_bytes(output_blob)
    finally:
        if output_blob.pbData:
            kernel32.LocalFree(output_blob.pbData)


def load_state() -> dict[str, object] | None:
    state_path = get_state_path()
    guard = _load_guard()
    registry_anchor = _load_registry_anchor()

    if not state_path.exists():
        if guard is not None or _anchor_requires_state(registry_anchor):
            raise ProtectedStateError("Protected authentication state is missing.")
        return None

    try:
        decrypted = _unprotect_bytes(state_path.read_bytes())
        payload = json.loads(decrypted.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ProtectedStateError(
            "Protected authentication state is unreadable."
        ) from exc

    if not isinstance(payload, dict):
        raise ProtectedStateError("Protected authentication state is invalid.")

    install_id = str(payload.get("install_id") or "").strip()
    integrity_key = str(payload.get("integrity_key") or "").strip()
    password_hash = str(payload.get("password_hash") or "").strip()
    if not install_id or not integrity_key:
        raise ProtectedStateError("Protected authentication state is incomplete.")

    _validate_install_anchor(
        guard,
        state_install_id=install_id,
        password_hash=password_hash,
        anchor_name="file-based",
    )
    _validate_install_anchor(
        registry_anchor,
        state_install_id=install_id,
        password_hash=password_hash,
        anchor_name="registry",
    )

    return payload


def save_state(state: dict[str, object]) -> None:
    state = dict(state)
    state["updated_at"] = time.time()
    encoded = json.dumps(state, sort_keys=True).encode("utf-8")
    protected = _protect_bytes(encoded)
    _write_bytes_atomic(get_state_path(), protected)
    auth_configured = bool(str(state.get("password_hash") or "").strip())
    _save_guard(state, auth_configured=auth_configured)
    _save_registry_anchor(state, auth_configured=auth_configured)


def ensure_state() -> dict[str, object]:
    existing = load_state()
    if existing is not None:
        return existing

    state = _build_default_state()
    save_state(state)
    return state


def update_state(**changes: object) -> dict[str, object]:
    state = ensure_state()
    state.update(changes)
    save_state(state)
    return state


def get_integrity_key() -> bytes:
    state = ensure_state()
    try:
        return base64.b64decode(str(state.get("integrity_key") or "").encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ProtectedStateError("Protected integrity key is invalid.") from exc


def secure_delete_file(path: Path, passes: int = 3) -> None:
    if not path.exists():
        return

    try:
        file_size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except OSError:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
