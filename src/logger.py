import contextlib
import inspect
import json
import logging
import sys
import traceback
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from typing import Any
from uuid import uuid4

correlation_id: ContextVar[str] = ContextVar("correlation_id")
start_time: ContextVar[datetime] = ContextVar("start_time")
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
        aFrame = sys._getframe(frame_level)
        info = inspect.getframeinfo(aFrame)
        log = {
            "level": level_map[level],
        }
        if message:
            log["message"] = message
        log["timestamp"] = datetime.now(timezone.utc).isoformat()
        log["path"] = f"{info.filename}:{info.lineno}"
        if id := correlation_id.get(None):
            log["correlation_id"] = id
        if start_time.get(None):
            log["duration"] = str(datetime.now(timezone.utc) - start_time.get())
        if self.name:
            log["module"] = self.name
        if extras_data := extras.get(None):
            log.update(extras_data)
        if data:
            log.update(data)
        if level > logging.WARNING:
            log.update({"traceback": traceback.format_exc()})
        return log

    def _exception(self, message, data: dict[str, Any] | None | None = None):
        self._log(self.EXCEPTION_LEVEL, message, data)

    def _log(self, level, message, data: dict | None | None = None, frame_level=2):
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

    def add_extras(self, extras_data):
        return extras.set({**extras.get({}), **extras_data})

    def extract_args(self, func, args, kwargs):
        args_name = inspect.signature(func).parameters.keys()
        return {**dict(zip(args_name, args)), **kwargs}

    def attach_logger(
        self,
        attach_correlation_id: bool = True,
        attached_fields={},
        log_endpoint: bool = False,
    ):
        """
        This is a Python function that attaches a logger to a given function, with options to include a
        correlation ID, additional fields, and endpoint information.

        :param attach_correlation_id: A boolean parameter that determines whether or not to attach a
        unique correlation ID to the log messages. If set to True, a new UUID will be generated and
        attached to the log messages. If set to False, no correlation ID will be attached, defaults to
        True
        :type attach_correlation_id: bool (optional)
        :param attached_fields: `attached_fields` is a dictionary that contains additional fields to be
        logged along with the function call. The keys of the dictionary represent the names of the
        fields to be logged, and the values represent the corresponding argument names of the function.
        If the argument is not provided, the default value of the argument
        :param is_lambda: A boolean parameter that indicates whether the function being decorated is a
        Lambda function or not. If it is a Lambda function, the decorator will wrap the function with
        additional functionality to handle Lambda-specific event and context parameters, defaults to
        False
        :type is_lambda: bool (optional)
        :param log_endpoint: log_endpoint is a boolean parameter that determines whether to include
        additional logging information related to the endpoint being called, such as the user agent,
        operation name, IP address, and field names. If set to True, this information will be added to
        the log record as extra data, defaults to False
        :type log_endpoint: bool (optional)
        :return: The function `attach_logger` is returning a decorator function
        `decorator_attach_logger`.
        """

        def decorator_attach_logger(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                args_dict = self.extract_args(func, args, kwargs)
                local_extras = {}
                id = None
                if attach_correlation_id:
                    id = correlation_id.set(str(uuid4()))
                if len(attached_fields) > 0:
                    local_extras.update(
                        dict(
                            {
                                value: args_dict[field]
                                if args_dict.get(field, None)
                                else (
                                    inspect.signature(func).parameters[field].default
                                    if inspect.signature(func).parameters[field].default
                                    != inspect._empty
                                    else None
                                )
                                for field, value in attached_fields.items()
                            }
                        )
                    )
                if log_endpoint:
                    info = args_dict.get("info", None)
                    if info:
                        local_extras.update(
                            {
                                "source": info.context["request"].headers.get(
                                    "user-agent"
                                ),
                                "operation": info.operation.operation.name,
                                # Will detect if the name exists x-forwarded-for and REMOTE_ADDR
                                "ip_address": info.context["request"].headers.get(
                                    "x-forwarded-for"
                                )
                                or info.context["request"].headers.get("REMOTE_ADDR")
                                or "n/a",
                                "field_names": info.field_name,
                            }
                        )
                if len(local_extras) > 0:
                    self.add_extras(local_extras)
                result = func(*args, **kwargs)
                if id and attach_correlation_id:
                    correlation_id.reset(id)
                return result

            return wrapper

        return decorator_attach_logger

    @contextlib.contextmanager
    def logger_context(
        self, attach_correlation_id: bool = True, extras_data: dict[str, Any] | None = None
    ):
        """
        This is a context manager function that attaches a logger context with an optional correlation
        ID.

        :param attach_correlation_id: A boolean parameter that determines whether or not to attach a
        correlation ID to the logger context. If set to True, a new correlation ID will be generated and
        attached to the logger context. If set to False, no correlation ID will be attached, defaults to
        True
        :type attach_correlation_id: bool (optional)
        """
        id = None
        if attach_correlation_id:
            id = correlation_id.set(str(uuid4()))
        extras_token = None
        if extras_data:
            extras_token = self.add_extras(extras_data)
        try:
            yield
        finally:
            if id and attach_correlation_id:
                correlation_id.reset(id)
            if extras_token and extras_data:
                extras.reset(extras_token)

    def record_time(self, func):
        """
        This function records the execution time of a given function and returns a wrapper function that
        can be used to call the original function with the added functionality of recording the
        execution time.

        :param func: `func` is a function that will be timed and recorded. It is the function that will
        be passed as an argument to the `record_time` method
        :param is_lambda: is a boolean parameter that indicates whether the function being decorated is
        a lambda function or not. If it is a lambda function, the decorator will wrap it with a
        lambda_wrapper function that takes in event and context parameters in addition to any other
        arguments. If it is not a lambda function, the decorator will, defaults to False
        :type is_lambda: bool (optional)
        :return: The `record_time` function returns a wrapper function that records the execution time
        of the input function. The returned wrapper function either takes in `event` and `context`
        parameters (if `is_lambda` is True) or `*args` and `**kwargs` parameters (if `is_lambda` is
        False) and returns the output of the input function.
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            time_token = start_time.set(datetime.now(timezone.utc))
            cur_func = func(*args, **kwargs)
            start_time.reset(time_token)
            return cur_func

        return wrapper

    @contextlib.contextmanager
    def record_time_context(self):
        time_token = None
        try:
            time_token = start_time.set(datetime.now(timezone.utc))
            yield
        finally:
            if time_token:
                start_time.reset(time_token)
