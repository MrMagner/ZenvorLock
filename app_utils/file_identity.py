from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path

from app_utils.software_inventory import normalize_path


_IDENTITY_LOCK = threading.RLock()
_HASH_CACHE: dict[str, tuple[int, int, int, str, float]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes


def file_sha256(path: str | os.PathLike[str] | None) -> str:
    normalized = normalize_path(path)
    if not normalized:
        return ""

    file_path = Path(normalized)
    try:
        stat = file_path.stat()
    except OSError:
        return ""

    cache_key = normalized.casefold()
    now = time.time()
    with _IDENTITY_LOCK:
        cached = _HASH_CACHE.get(cache_key)
        if cached is not None:
            cached_mtime, cached_size, cached_ctime, cached_hash, cached_at = cached
            if (
                cached_mtime == stat.st_mtime_ns
                and cached_size == stat.st_size
                and cached_ctime == stat.st_ctime_ns
                and (now - cached_at) < _CACHE_TTL_SECONDS
            ):
                return cached_hash

    hasher = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError:
        return ""

    digest = hasher.hexdigest()
    with _IDENTITY_LOCK:
        _HASH_CACHE[cache_key] = (
            stat.st_mtime_ns,
            stat.st_size,
            stat.st_ctime_ns,
            digest,
            now,
        )
    return digest


def invalidate_cache(path: str | os.PathLike[str] | None) -> None:
    normalized = normalize_path(path)
    if not normalized:
        return
    cache_key = normalized.casefold()
    with _IDENTITY_LOCK:
        _HASH_CACHE.pop(cache_key, None)


def invalidate_all_cache() -> None:
    with _IDENTITY_LOCK:
        _HASH_CACHE.clear()


def matches_expected_sha256(
    path: str | os.PathLike[str] | None, expected_sha256: str | None
) -> bool:
    expected = str(expected_sha256 or "").strip().lower()
    if not expected:
        return True
    return file_sha256(path) == expected
