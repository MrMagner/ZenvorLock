import logging
import re
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app_utils.paths import APP_NAME, get_log_file_path

_SENSITIVE_PATTERNS = [
    (
        re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*[^\s,]{8,}"),
        r"\1=***REDACTED***",
    ),
    (
        re.compile(r"(?i)(hash|hash_value)\s*[=:]\s*[a-fA-F0-9]{32,}"),
        r"\1=***REDACTED***",
    ),
    (re.compile(r"C:\\Users\\[^\\]+"), r"C:\\Users\\***USER***"),
]


def _sanitize_log_message(message: str) -> str:
    for pattern, replacement in _SENSITIVE_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _sanitize_log_message(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: _sanitize_log_message(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    _sanitize_log_message(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        try:
            record.getMessage()
        except Exception:
            if record.args and isinstance(record.args, tuple):
                record.args = tuple(
                    repr(a) if not isinstance(a, str) else a for a in record.args
                )
        return True


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("SecureAppLocker")
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler = _build_handler(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.addFilter(SensitiveDataFilter())
    logger.propagate = False
    return logger


def _build_handler(formatter: logging.Formatter) -> logging.Handler:
    candidate_paths = [
        Path(tempfile.gettempdir()) / "zenvor.log",
    ]

    for log_path in candidate_paths:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                log_path,
                encoding="utf-8",
                delay=True,
                maxBytes=512 * 1024,
                backupCount=3,
            )
            handler.setFormatter(formatter)
            return handler
        except OSError:
            continue

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    return handler


logger = setup_logger()
