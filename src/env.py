import logging
import os

logger = logging.getLogger(__name__)


def getenv(name: str) -> str | None:
    """Read ``STR_<name>``, falling back to the deprecated ``TEMV_<name>``."""
    value = os.getenv(f"STR_{name}")
    if value is not None:
        return value
    legacy = os.getenv(f"TEMV_{name}")
    if legacy is not None:
        logger.warning(f"TEMV_{name} is deprecated; use STR_{name}")
    return legacy
