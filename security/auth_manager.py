from __future__ import annotations

import base64
import secrets
import time
import unicodedata

import bcrypt

from app_utils.logger import logger
from config.config_manager import get_connection
from security.audit import log_security_event
from security.protected_state import (
    ProtectedStateError,
    ensure_state,
    load_state,
    save_state,
)

MAX_FAILED_ATTEMPTS = 5
BASE_LOCKOUT_DURATION = 60  # seconds
MAX_LOCKOUT_DURATION = 3600  # 1 hour maximum
MIN_PASSWORD_LENGTH = 12


def get_master_password_policy_hint() -> str:
    return (
        f"Use at least {MIN_PASSWORD_LENGTH} characters and include all of "
        "these: uppercase letters, lowercase letters, numbers, and symbols."
    )


def generate_recovery_key() -> str:
    raw = secrets.token_bytes(16)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _normalize_password(password: str | None) -> str:
    return str(password or "")


def _zero_buffer(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _load_runtime_state() -> dict[str, object]:
    return ensure_state()


def validate_master_password_strength(password: str | None) -> str | None:
    candidate = _normalize_password(password)
    if len(candidate) < MIN_PASSWORD_LENGTH:
        return (
            f"Master password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )

    if not candidate.strip():
        return "Master password cannot be empty or whitespace only."

    category_count = sum(
        [
            any(character.isupper() for character in candidate),
            any(character.islower() for character in candidate),
            any(character.isdigit() for character in candidate),
            any(
                not character.isalnum()
                and not unicodedata.category(character).startswith("Z")
                for character in candidate
            ),
        ]
    )
    if category_count < 4:
        return (
            "Master password must include all of these: uppercase letters, "
            "lowercase letters, numbers, and symbols."
        )

    common_patterns = [
        "password",
        "123456",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
    ]
    lowered = candidate.lower()
    for pattern in common_patterns:
        if pattern in lowered:
            return "Master password must not contain common words or patterns."

    if len(set(candidate)) < 6:
        return "Master password must use more unique characters."

    return None


def _load_legacy_password_hash() -> str:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = 'admin' LIMIT 1"
        ).fetchone()
        return str(row["password_hash"] or "").strip() if row else ""
    finally:
        conn.close()


def _clear_legacy_password_rows() -> None:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM users WHERE username = 'admin'")
        conn.commit()
    finally:
        conn.close()


def prepare_auth_runtime() -> tuple[bool, str]:
    try:
        state = _load_runtime_state()
        if not str(state.get("password_hash") or "").strip():
            legacy_hash = _load_legacy_password_hash()
            if legacy_hash:
                state["password_hash"] = legacy_hash
                state["failed_attempts"] = 0
                state["lockout_until"] = 0.0
                save_state(state)
                _clear_legacy_password_rows()
                log_security_event(
                    "PASSWORD_STORE_MIGRATION",
                    "Migrated master password to protected runtime state.",
                )
        return True, ""
    except ProtectedStateError:
        logger.error("Protected authentication state is unavailable or tampered.")
        return False, "Secure authentication state is unavailable or appears tampered."
    except Exception as exc:
        logger.error("Error preparing authentication runtime: %s", exc)
        return False, "Failed to prepare the protected authentication state."


def get_lockout_time() -> float:
    try:
        state = _load_runtime_state()
    except ProtectedStateError:
        return float(BASE_LOCKOUT_DURATION)

    lockout_until = state.get("lockout_until")
    try:
        lockout_until_float = float(lockout_until) if lockout_until else 0.0
    except (TypeError, ValueError):
        lockout_until_float = 0.0
    remaining = lockout_until_float - time.time()
    return remaining if remaining > 0 else 0.0


def _calculate_exponential_lockout(lockout_count: int) -> float:
    duration = BASE_LOCKOUT_DURATION * (2**lockout_count)
    return min(duration, MAX_LOCKOUT_DURATION)


def record_failed_attempt() -> None:
    try:
        state = _load_runtime_state()
    except ProtectedStateError:
        return

    lockout_until = state.get("lockout_until")
    try:
        lockout_until_float = float(lockout_until) if lockout_until else 0.0
    except (TypeError, ValueError):
        lockout_until_float = 0.0

    if lockout_until_float > time.time():
        return

    failed_attempts = int(state.get("failed_attempts") or 0) + 1
    state["failed_attempts"] = failed_attempts
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        lockout_count = int(state.get("lockout_count") or 0) + 1
        state["lockout_count"] = lockout_count
        state["failed_attempts"] = 0
        state["lockout_until"] = time.time() + _calculate_exponential_lockout(
            lockout_count
        )
        log_security_event(
            "LOCKOUT_ESCALATED",
            f"Account lockout #{lockout_count} triggered after {MAX_FAILED_ATTEMPTS} failed attempts. "
            f"Lockout duration: {_calculate_exponential_lockout(lockout_count)}s.",
        )
    save_state(state)


def reset_failed_attempts() -> None:
    try:
        state = _load_runtime_state()
    except ProtectedStateError:
        return

    state["failed_attempts"] = 0
    state["lockout_until"] = 0.0
    state["lockout_count"] = 0
    save_state(state)


def setup_master_password(password: str) -> tuple[bool, str]:
    password = _normalize_password(password)
    validation_error = validate_master_password_strength(password)
    if validation_error:
        logger.warning(
            "Rejected weak master password during setup: %s", validation_error
        )
        return False, validation_error

    try:
        state = _load_runtime_state()
        if str(state.get("password_hash") or "").strip():
            logger.warning(
                "Attempted to reset existing master password without verification."
            )
            return False, "A master password is already configured."

        password_bytes = bytearray(password.encode("utf-8"))
        try:
            hashed = bcrypt.hashpw(bytes(password_bytes), bcrypt.gensalt())
        finally:
            _zero_buffer(password_bytes)

        recovery_key = generate_recovery_key()
        recovery_key_bytes = bytearray(recovery_key.encode("utf-8"))
        try:
            recovery_hash = bcrypt.hashpw(
                bytes(recovery_key_bytes), bcrypt.gensalt()
            ).decode("utf-8")
        finally:
            _zero_buffer(recovery_key_bytes)

        state["password_hash"] = hashed.decode("utf-8")
        state["recovery_hash"] = recovery_hash
        state["failed_attempts"] = 0
        state["lockout_until"] = 0.0
        state["lockout_count"] = 0
        save_state(state)
        _clear_legacy_password_rows()
        log_security_event("PASSWORD_SET", "Configured master password.")
        return True, recovery_key
    except Exception as exc:
        logger.error("Error setting master password: %s", exc)
        return False, "Failed to save the master password."


def reset_password_with_recovery_key(
    recovery_key: str, new_password: str
) -> tuple[bool, str]:
    recovery_key = str(recovery_key or "").strip().upper()
    if not recovery_key:
        return False, "Recovery key is required."

    validation_error = validate_master_password_strength(new_password)
    if validation_error:
        return False, validation_error

    try:
        state = _load_runtime_state()
        stored_recovery_hash = str(state.get("recovery_hash") or "").strip()
        if not stored_recovery_hash:
            return False, "No recovery key is configured for this installation."

        key_bytes = bytearray(recovery_key.encode("utf-8"))
        stored_hash_bytes = bytearray(stored_recovery_hash.encode("utf-8"))
        try:
            verified = bcrypt.checkpw(bytes(key_bytes), bytes(stored_hash_bytes))
        finally:
            _zero_buffer(key_bytes)
            _zero_buffer(stored_hash_bytes)

        if not verified:
            log_security_event("RECOVERY_FAILURE", "Invalid recovery key attempted.")
            return False, "Recovery key is incorrect."

        password_bytes = bytearray(_normalize_password(new_password).encode("utf-8"))
        try:
            hashed = bcrypt.hashpw(bytes(password_bytes), bcrypt.gensalt())
        finally:
            _zero_buffer(password_bytes)

        new_recovery_key = generate_recovery_key()
        new_recovery_key_bytes = bytearray(new_recovery_key.encode("utf-8"))
        try:
            new_recovery_hash = bcrypt.hashpw(
                bytes(new_recovery_key_bytes), bcrypt.gensalt()
            ).decode("utf-8")
        finally:
            _zero_buffer(new_recovery_key_bytes)

        state["password_hash"] = hashed.decode("utf-8")
        state["recovery_hash"] = new_recovery_hash
        state["failed_attempts"] = 0
        state["lockout_until"] = 0.0
        state["lockout_count"] = 0
        save_state(state)
        log_security_event("PASSWORD_RECOVERY", "Password reset via recovery key.")
        return True, new_recovery_key
    except ProtectedStateError:
        return False, "Protected authentication state is unavailable."
    except Exception as exc:
        logger.error("Error resetting password with recovery key: %s", exc)
        return False, "Failed to reset the password."


def verify_master_password(password: str) -> bool:
    if get_lockout_time() > 0:
        return False

    try:
        state = _load_runtime_state()
        stored_hash = str(state.get("password_hash") or "").strip()
        if not stored_hash:
            record_failed_attempt()
            return False

        password_bytes = bytearray(_normalize_password(password).encode("utf-8"))
        stored_hash_bytes = bytearray(stored_hash.encode("utf-8"))
        try:
            verified = bcrypt.checkpw(bytes(password_bytes), bytes(stored_hash_bytes))
        finally:
            _zero_buffer(password_bytes)
            _zero_buffer(stored_hash_bytes)

        if verified:
            reset_failed_attempts()
            log_security_event("AUTH_SUCCESS", "Verified master password.")
            return True

        record_failed_attempt()
        log_security_event("AUTH_FAILURE", "Rejected invalid master password.")
        return False
    except ProtectedStateError:
        logger.error(
            "Protected authentication state is unavailable during verification."
        )
        return False
    except Exception as exc:
        logger.error("Error verifying password: %s", exc)
        record_failed_attempt()
        return False


def change_master_password(
    previous_password: str, new_password: str
) -> tuple[bool, str]:
    previous_password = _normalize_password(previous_password)
    new_password = _normalize_password(new_password)

    if not previous_password:
        return False, "Enter the previous password."

    if not verify_master_password(previous_password):
        return False, "Previous password is incorrect."

    validation_error = validate_master_password_strength(new_password)
    if validation_error:
        return False, validation_error

    try:
        state = _load_runtime_state()
        password_bytes = bytearray(new_password.encode("utf-8"))
        try:
            hashed = bcrypt.hashpw(bytes(password_bytes), bcrypt.gensalt())
        finally:
            _zero_buffer(password_bytes)

        state["password_hash"] = hashed.decode("utf-8")
        state["failed_attempts"] = 0
        state["lockout_until"] = 0.0
        save_state(state)
        _clear_legacy_password_rows()
        log_security_event("PASSWORD_CHANGE", "Updated master password.")
        return True, "Master password changed successfully."
    except Exception as exc:
        logger.error("Error changing master password: %s", exc)
        return False, "Failed to change the master password."


def is_master_password_set() -> bool:
    try:
        state = load_state()
    except ProtectedStateError:
        return True
    if state is None:
        return False
    return bool(str(state.get("password_hash") or "").strip())
