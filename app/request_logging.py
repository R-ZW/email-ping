"""Middleware ASGI de access log sem exposição de dados da requisição."""

from __future__ import annotations

import logging
import re
import time
import uuid
from http import HTTPStatus
from typing import Any

from app.logging_config import ACCESS_LOGGER_NAME, APP_LOGGER_NAME, redact_sensitive_text


class AccessLogMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app
        self.access_logger = logging.getLogger(ACCESS_LOGGER_NAME)
        self.app_logger = logging.getLogger(APP_LOGGER_NAME)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["request_id"] = request_id

        started_at = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            self.app_logger.exception(
                "unhandled request exception",
                extra={
                    "event": "unhandled_exception",
                    "request_id": request_id,
                    "method": scope.get("method"),
                    "route": _route_pattern(scope),
                    "client_ip": _client_ip(scope),
                },
            )
            raise
        finally:
            duration_ms = round((time.perf_counter() - started_at) * 1000, 3)
            fields = {
                "event": "http_request",
                "request_id": request_id,
                "client_ip": _client_ip(scope),
                "client_address": _client_address(scope),
                "method": scope.get("method"),
                "route": _route_pattern(scope),
                "http_version": scope.get("http_version"),
                "status": status_code,
                "status_phrase": _status_phrase(status_code),
                "duration_ms": duration_ms,
                "user_agent": _header(scope, b"user-agent"),
                "user": _authenticated_user(state),
            }
            self.access_logger.info("request completed", extra=fields)
            if status_code >= 500:
                self.app_logger.error("server response", extra=fields)


def _route_pattern(scope: dict) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    request_path = scope.get("path", "")
    if path == "/static" and request_path.startswith("/static/"):
        return _safe_raw_path(request_path)
    return path if isinstance(path, str) else _safe_raw_path(request_path)


_UUID_PATTERN = re.compile(
    r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_LONG_OPAQUE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def _safe_raw_path(path: str) -> str:
    redacted_uuid = _UUID_PATTERN.sub("{id}", path)
    segments = [
        "{redacted}" if _LONG_OPAQUE_SEGMENT.fullmatch(segment) else segment
        for segment in redacted_uuid.split("/")
    ]
    return "/".join(segments) or "/"


def _client_ip(scope: dict) -> str | None:
    client = scope.get("client")
    return client[0] if client else None


def _client_address(scope: dict) -> str:
    client = scope.get("client")
    if not client:
        return "-"
    host, port = client
    formatted_host = f"[{host}]" if ":" in host else host
    return f"{formatted_host}:{port}"


def _status_phrase(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return ""


def _header(scope: dict, name: bytes) -> str | None:
    for header_name, value in scope.get("headers", []):
        if header_name.lower() == name:
            return redact_sensitive_text(
                value.decode("latin-1", errors="replace")[:512]
            )
    return None


def _authenticated_user(state: dict) -> str | None:
    user = state.get("authenticated_user")
    if user is None:
        return None
    username = getattr(user, "username", user)
    return str(username)[:128]
