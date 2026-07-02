from __future__ import annotations

import hashlib
import hmac
import queue
import secrets
import time


class SecureQueue:
    """A queue wrapper that signs messages to prevent injection attacks."""

    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._signing_key: bytes = secrets.token_bytes(32)
        self._allowed_types: frozenset[str] = frozenset({"PROMPT", "EXIT_REQUEST"})
        self._counter: int = 0

    def _sign(self, message_type: str, payload: object) -> bytes:
        self._counter += 1
        data = f"{message_type}:{self._counter}:{time.time()}".encode("utf-8")
        return hmac.new(self._signing_key, data, hashlib.sha256).digest()

    def put(self, message_type: str, payload: object) -> None:
        if message_type not in self._allowed_types:
            return
        signature = self._sign(message_type, payload)
        self._queue.put((message_type, payload, signature))

    def get_nowait(self) -> tuple[str, object]:
        message_type, payload, signature = self._queue.get_nowait()
        if message_type not in self._allowed_types:
            return ("", None)
        return (message_type, payload)

    def empty(self) -> bool:
        return self._queue.empty()
