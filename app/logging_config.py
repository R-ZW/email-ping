"""Configuração central de logs persistentes e eventos de auditoria."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from app.config import LOG_BACKUP_COUNT, LOG_DIR, LOG_LEVEL, LOG_MAX_BYTES

ACCESS_LOGGER_NAME = "email_ping.access"
APP_LOGGER_NAME = "email_ping.app"

_MANAGED_HANDLER_ATTR = "_email_ping_managed_handler"
_configured = False

_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\bepat_[A-Za-z0-9_-]+\b"),
    re.compile(
        r"(?i)\b(?:password|cookie|authorization|csrf(?:_token)?|api[_-]?key|token)\s*[=:]\s*[^\s,;]+"
    ),
)
_SENSITIVE_FIELD_NAMES = frozenset(
    {"password", "cookie", "authorization", "csrf_token", "api_token", "api_key"}
)


class PlainTextFormatter(logging.Formatter):
    """Texto legível no estilo do Uvicorn, com timestamp e campos adicionais."""

    _standard_fields = frozenset(logging.makeLogRecord({}).__dict__)
    _ignored_fields = frozenset({"color_message"})

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        prefix = f"{timestamp} {record.levelname}:     "
        if getattr(record, "event", None) == "http_request":
            return prefix + self._format_access(record)

        line = prefix + _single_line(record.getMessage())
        fields = []
        for key, value in record.__dict__.items():
            if (
                key in self._standard_fields
                or key in self._ignored_fields
                or key.startswith("_")
            ):
                continue
            if key == "event" and value == "log":
                continue
            safe_value = "[redacted]" if key.lower() in _SENSITIVE_FIELD_NAMES else redact_sensitive_text(value)
            fields.append(f"{key}={_format_value(safe_value)}")
        if fields:
            line += " " + " ".join(fields)
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line

    @staticmethod
    def _format_access(record: logging.LogRecord) -> str:
        request_line = (
            f'{getattr(record, "client_address", "-")} - '
            f'"{getattr(record, "method", "-")} '
            f'{_single_line(getattr(record, "route", "<unmatched>"))} '
            f'HTTP/{getattr(record, "http_version", "-")}" '
            f'{getattr(record, "status", 500)} '
            f'{getattr(record, "status_phrase", "")}'
        ).rstrip()
        fields = [
            f'request_id={_format_value(getattr(record, "request_id", None))}',
            f'duration_ms={_format_value(getattr(record, "duration_ms", None))}',
        ]
        user = getattr(record, "user", None)
        if user:
            fields.append(f"user={_format_value(user)}")
        user_agent = getattr(record, "user_agent", None)
        if user_agent:
            fields.append(f"user_agent={_format_value(user_agent)}")
        return request_line + " " + " ".join(fields)


class SecureRotatingFileHandler(RotatingFileHandler):
    """Mantém permissão 0640 também após cada rotação no Linux."""

    def _open(self):
        stream = super()._open()
        if os.name == "posix":
            Path(self.baseFilename).chmod(0o640)
        return stream


def _single_line(value: Any) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def redact_sensitive_text(value: Any) -> Any:
    """Redige credenciais mesmo quando forem incluídas em campos registráveis."""
    if not isinstance(value, str):
        return value
    redacted = value
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub("[redacted]", redacted)
    return redacted


def _format_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = _single_line(value)
    allowed = "._:/{}@+-"
    if text and all(character.isalnum() or character in allowed for character in text):
        return text
    return json.dumps(text, ensure_ascii=False)


def _validate_settings(level: str, max_bytes: int, backup_count: int) -> None:
    if level.upper() not in logging.getLevelNamesMapping():
        raise ValueError(f"LOG_LEVEL inválido: {level!r}")
    if max_bytes <= 0:
        raise ValueError("LOG_MAX_BYTES deve ser maior que zero.")
    if backup_count < 0:
        raise ValueError("LOG_BACKUP_COUNT não pode ser negativo.")


def _prepare_log_dir(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        log_dir.chmod(0o750)


def _mark_managed(handler: logging.Handler) -> logging.Handler:
    setattr(handler, _MANAGED_HANDLER_ATTR, True)
    return handler


def _remove_managed_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        if getattr(handler, _MANAGED_HANDLER_ATTR, False):
            logger.removeHandler(handler)
            handler.close()


def _file_handler(
    path: Path,
    *,
    formatter: logging.Formatter,
    max_bytes: int,
    backup_count: int,
) -> RotatingFileHandler:
    handler = SecureRotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)
    _mark_managed(handler)
    return handler


def _console_handler(formatter: logging.Formatter) -> logging.StreamHandler:
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    _mark_managed(handler)
    return handler


def configure_logging(
    *,
    log_dir: Path | None = None,
    level: str | None = None,
    max_bytes: int | None = None,
    backup_count: int | None = None,
    force: bool = False,
) -> tuple[Path, Path]:
    """Configura console, arquivos rotativos e captura de erros do Uvicorn.

    Os parâmetros existem para permitir testes isolados. Em execução normal os
    valores vêm exclusivamente de app.config / variáveis de ambiente.
    """

    global _configured

    resolved_dir = Path(log_dir) if log_dir is not None else LOG_DIR
    resolved_level = (level or LOG_LEVEL).upper()
    resolved_max_bytes = max_bytes if max_bytes is not None else LOG_MAX_BYTES
    resolved_backup_count = (
        backup_count if backup_count is not None else LOG_BACKUP_COUNT
    )
    _validate_settings(
        resolved_level, resolved_max_bytes, resolved_backup_count
    )

    access_path = resolved_dir / "access.log"
    app_path = resolved_dir / "app.log"
    if _configured and not force:
        return access_path, app_path

    _prepare_log_dir(resolved_dir)
    formatter = PlainTextFormatter()
    numeric_level = logging.getLevelNamesMapping()[resolved_level]

    access_logger = logging.getLogger(ACCESS_LOGGER_NAME)
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    uvicorn_error_logger = logging.getLogger("uvicorn.error")

    for logger in (access_logger, app_logger, uvicorn_error_logger):
        _remove_managed_handlers(logger)

    access_logger.setLevel(numeric_level)
    access_logger.propagate = False
    access_logger.addHandler(_console_handler(formatter))
    access_logger.addHandler(
        _file_handler(
            access_path,
            formatter=formatter,
            max_bytes=resolved_max_bytes,
            backup_count=resolved_backup_count,
        )
    )

    app_logger.setLevel(numeric_level)
    app_logger.propagate = False
    app_logger.addHandler(_console_handler(formatter))
    app_file_handler = _file_handler(
        app_path,
        formatter=formatter,
        max_bytes=resolved_max_bytes,
        backup_count=resolved_backup_count,
    )
    app_logger.addHandler(app_file_handler)

    # Substituímos o console herdado do Uvicorn para que startup, shutdown e
    # erros usem o mesmo formato com timestamp empregado nos arquivos.
    uvicorn_error_logger.setLevel(numeric_level)
    uvicorn_error_logger.propagate = False
    uvicorn_error_logger.addHandler(_console_handler(formatter))
    uvicorn_error_logger.addHandler(app_file_handler)

    # O access logger padrão inclui URL/query string reais. Nosso middleware
    # substitui essa saída por rotas normalizadas e sem parâmetros sensíveis.
    logging.getLogger("uvicorn.access").disabled = True

    _configured = True
    return access_path, app_path


def audit_event(
    event: str,
    *,
    actor: str | None = None,
    actor_role: str | None = None,
    client_ip: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    outcome: str = "success",
    request_id: str | None = None,
) -> None:
    """Registra uma ação auditável sem aceitar conteúdo livre ou credenciais."""

    logging.getLogger(APP_LOGGER_NAME).info(
        "audit event",
        extra={
            "event": event,
            "actor": redact_sensitive_text(actor or "anonymous"),
            "actor_role": actor_role,
            "client_ip": client_ip,
            "action": action,
            "target_type": target_type,
            "target_id": _safe_target_id(target_id),
            "outcome": outcome,
            "request_id": request_id,
        },
    )


def _safe_target_id(target_id: str | int | None) -> str | int | None:
    if target_id is None or isinstance(target_id, int):
        return target_id
    digest = hashlib.sha256(target_id.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


def reset_logging_for_tests() -> None:
    """Remove somente handlers gerenciados por este módulo."""

    global _configured
    for name in (ACCESS_LOGGER_NAME, APP_LOGGER_NAME, "uvicorn.error"):
        _remove_managed_handlers(logging.getLogger(name))
    logging.getLogger("uvicorn.error").propagate = True
    logging.getLogger("uvicorn.access").disabled = False
    _configured = False
