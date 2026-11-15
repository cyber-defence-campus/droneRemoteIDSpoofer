"""
Logging for failures that may repeat on every packet or every few seconds (a full disk, a locked
database, a malformed field a node keeps sending): the first failure of each kind is logged at the
given level with its traceback, later ones at debug level only, so a persistent failure shows in
the journal without flooding it. The kind is a short key chosen by the caller plus the exception
type, so a different failure at the same place is reported again.
"""

import logging
from typing import Optional, Set, Tuple

_reported: Set[Tuple[str, str]] = set()


def log_failure(logger: logging.Logger, key: str, message: str, exc: Optional[BaseException] = None,
                level: int = logging.WARNING) -> None:
    """Logs message (with exc appended), at level the first time per (key, exception type)."""
    kind = (key, type(exc).__name__ if exc is not None else "")
    text = f"{message}: {type(exc).__name__}: {exc}" if exc is not None else message
    if kind in _reported:
        logger.debug(text)
        return
    _reported.add(kind)
    logger.log(level, text + " (repeats are logged at debug level)",
               exc_info=(type(exc), exc, exc.__traceback__) if exc is not None else None)


def close_or_warn(logger: logging.Logger, resource, what: str) -> None:
    """Closes resource (file, socket, connection); a failure, which should not happen, is a warning."""
    try:
        resource.close()
    except Exception as e:
        log_failure(logger, f"close {what}", f"[!] Could not close {what}", e)
