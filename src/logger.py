import contextlib
import json
import logging
import sys
import traceback
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

correlation_id: ContextVar[str] = ContextVar("correlation_id")
extras: ContextVar[dict] = ContextVar("extras", default={})


class Logging:
    EXCEPTION_LEVEL = 60
    name = None

    def __init__(self, name=None):
        if name:
            self.name = name
            self.logger = logging.getLogger(name)
        else:
            self.logger = logging.getLogger()
        console_handler = logging.StreamHandler()
        self.logger.addHandler(console_handler)
        for h in self.logger.handlers:
            h.setFormatter(logging.Formatter("%(message)s"))
        self.logger.setLevel(logging.INFO)

    def build_log(self, level, message, data, frame_level):
        level_map = {
            60: "EXCEPTION",
            50: "CRITICAL",
            40: "ERROR",
            30: "WARNING",
            20: "INFO",
            10: "DEBUG",
            0: "NOTSET",
        }
        frame = sys._getframe(frame_level)
        import inspect
        info = inspect.getframeinfo(frame)
        log: dict[str, Any] = {"level": level_map[level]}
        if message:
            log["message"] = message
        log["timestamp"] = datetime.now(timezone.utc).isoformat()
        log["path"] = f"{info.filename}:{info.lineno}"
        if cid := correlation_id.get(None):
            log["correlation_id"] = cid
        if self.name:
            log["module"] = self.name
        if extras_data := extras.get(None):
            log.update(extras_data)
        if data:
            log.update(data)
        if level > logging.WARNING:
            log["traceback"] = traceback.format_exc()
        return log

    def _log(self, level, message, data: dict | None = None, frame_level=2):
        self.logger.log(
            level,
            json.dumps(self.build_log(level, message, data, frame_level), default=str),
        )

    def info(self, message: str | None = None, data: dict[str, Any] | None = None):
        self._log(logging.INFO, message, data, 3)

    def warn(self, message: str | None = None, data: dict[str, Any] | None = None):
        self._log(logging.WARNING, message, data, 3)

    def warning(self, message: str | None = None, data: dict[str, Any] | None = None):
        self._log(logging.WARNING, message, data, 3)

    def debug(self, message: str | None = None, data: dict[str, Any] | None = None):
        self._log(logging.DEBUG, message, data, 3)

    def error(self, message: str | None = None, data: dict[str, Any] | None = None):
        self._log(logging.ERROR, message, data, 3)

    def exception(self, message: str | None = None, data: dict[str, Any] | None = None):
        self._log(self.EXCEPTION_LEVEL, message, data, 3)

    def add_extras(self, extras_data: dict[str, Any]):
        return extras.set({**extras.get({}), **extras_data})

    @contextlib.contextmanager
    def logger_context(
        self,
        attach_correlation_id: bool = True,
        extras_data: dict[str, Any] | None = None,
    ):
        cid_token = None
        extras_token = None
        if attach_correlation_id:
            cid_token = correlation_id.set(str(uuid4()))
        if extras_data:
            extras_token = self.add_extras(extras_data)
        try:
            yield
        finally:
            if cid_token:
                correlation_id.reset(cid_token)
            if extras_token and extras_data:
                extras.reset(extras_token)
