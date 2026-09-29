from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import stat
import unittest
import uuid
from pathlib import Path

from app.logging_config import (
    ACCESS_LOGGER_NAME,
    APP_LOGGER_NAME,
    audit_event,
    configure_logging,
    reset_logging_for_tests,
)
from app.request_logging import AccessLogMiddleware


class _Route:
    path = "/pixel/{token}"


def _flush_logs() -> None:
    seen: set[int] = set()
    for name in (ACCESS_LOGGER_NAME, APP_LOGGER_NAME, "uvicorn.error"):
        for handler in logging.getLogger(name).handlers:
            if id(handler) not in seen:
                handler.flush()
                seen.add(id(handler))


async def _request(*, raises: bool = False, user_agent: bytes = b"agente-de-teste"):
    sent: list[dict] = []

    async def endpoint(scope, receive, send):
        scope["route"] = _Route()
        scope["state"]["authenticated_user"] = "pablo"
        if raises:
            raise RuntimeError("erro controlado para teste")
        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/pixel/token-super-secreto",
        "raw_path": b"/pixel/token-super-secreto",
        "query_string": b"password=senha-super-secreta",
        "root_path": "",
        "headers": [
            (b"user-agent", user_agent),
            (b"authorization", b"Bearer chave-super-secreta"),
            (b"cookie", b"session=cookie-super-secreto"),
        ],
        "client": ("203.0.113.10", 43210),
        "server": ("testserver", 80),
        "state": {},
    }
    await AccessLogMiddleware(endpoint)(scope, receive, send)
    return sent


class LoggingTests(unittest.TestCase):
    def setUp(self):
        reset_logging_for_tests()
        self.temp_dir = Path(__file__).parent / f".tmp_logging_{uuid.uuid4().hex}"
        self.temp_dir.mkdir()
        self.log_dir = self.temp_dir / "logs"

    def tearDown(self):
        reset_logging_for_tests()
        shutil.rmtree(self.temp_dir)

    def configure(self, *, max_bytes: int = 10_000, backup_count: int = 2):
        return configure_logging(
            log_dir=self.log_dir,
            level="INFO",
            max_bytes=max_bytes,
            backup_count=backup_count,
            force=True,
        )

    def test_request_log_is_structured_normalized_and_does_not_leak_secrets(self):
        access_path, app_path = self.configure()

        sent = asyncio.run(_request())
        _flush_logs()

        access_line = access_path.read_text(encoding="utf-8").splitlines()[-1]
        self.assertRegex(
            access_line,
            r"^\d{4}-\d{2}-\d{2}T.*[+-]\d{2}:\d{2} INFO:\s+",
        )
        self.assertIn(
            '203.0.113.10:43210 - "GET /pixel/{token} HTTP/1.1" 204 No Content',
            access_line,
        )
        self.assertIn("user=pablo", access_line)
        self.assertIn("user_agent=agente-de-teste", access_line)
        request_id_match = re.search(r"request_id=([0-9a-f]{32})", access_line)
        self.assertIsNotNone(request_id_match)

        response_start = next(
            message for message in sent if message["type"] == "http.response.start"
        )
        headers = dict(response_start["headers"])
        self.assertEqual(
            headers[b"x-request-id"].decode(), request_id_match.group(1)
        )

        combined = access_path.read_text(encoding="utf-8") + app_path.read_text(
            encoding="utf-8"
        )
        for secret in (
            "token-super-secreto",
            "senha-super-secreta",
            "chave-super-secreta",
            "cookie-super-secreto",
        ):
            self.assertNotIn(secret, combined)

    def test_unhandled_exception_is_written_to_app_log(self):
        access_path, app_path = self.configure()

        with self.assertRaisesRegex(RuntimeError, "erro controlado"):
            asyncio.run(_request(raises=True))
        _flush_logs()

        app_content = app_path.read_text(encoding="utf-8")
        access_line = access_path.read_text(encoding="utf-8").splitlines()[-1]
        self.assertIn("event=unhandled_exception", app_content)
        self.assertIn("RuntimeError: erro controlado para teste", app_content)
        self.assertIn(
            '"GET /pixel/{token} HTTP/1.1" 500 Internal Server Error',
            access_line,
        )

    def test_rotation_and_uvicorn_error_capture(self):
        _, app_path = self.configure(max_bytes=500, backup_count=2)
        logger = logging.getLogger(APP_LOGGER_NAME)
        for index in range(30):
            logger.info(
                "linha para provocar rotação",
                extra={"event": "rotation_test", "index": index, "padding": "x" * 80},
            )
        logging.getLogger("uvicorn.error").error("erro-uvicorn-identificável")
        _flush_logs()

        self.assertTrue(app_path.exists())
        self.assertTrue(Path(f"{app_path}.1").exists())
        all_parts = "".join(
            path.read_text(encoding="utf-8")
            for path in sorted(self.log_dir.glob("app.log*"))
        )
        self.assertIn("erro-uvicorn-identificável", all_parts)

    def test_audit_helper_hashes_string_target_identifiers(self):
        _, app_path = self.configure()
        raw_token = "9c84ee82-e570-4b22-a20c-4f90bbbeef00"
        audit_event(
            "token_deleted",
            actor="pablo",
            client_ip="203.0.113.10",
            action="delete",
            target_type="token",
            target_id=raw_token,
            request_id="request-test",
        )
        _flush_logs()

        line = app_path.read_text(encoding="utf-8").splitlines()[-1]
        self.assertIn("event=token_deleted", line)
        self.assertIn("actor=pablo", line)
        self.assertRegex(line, r"target_id=sha256:[0-9a-f]{12}")
        self.assertNotIn(raw_token, line)

    def test_credentials_in_loggable_fields_are_redacted(self):
        access_path, app_path = self.configure()
        user_agent_secret = "epat_user_agent_secret_value"
        audit_actor_secret = "epat_audit_actor_secret_value"

        asyncio.run(
            _request(user_agent=f"cliente Bearer {user_agent_secret}".encode())
        )
        audit_event("login_failed", actor=audit_actor_secret, action="login", outcome="denied")
        _flush_logs()

        combined = access_path.read_text(encoding="utf-8") + app_path.read_text(
            encoding="utf-8"
        )
        self.assertNotIn(user_agent_secret, combined)
        self.assertNotIn(audit_actor_secret, combined)
        self.assertIn("[redacted]", combined)

    @unittest.skipUnless(os.name == "posix", "permissões POSIX só existem no Linux")
    def test_log_permissions_are_restricted_on_posix(self):
        access_path, app_path = self.configure()
        self.assertEqual(stat.S_IMODE(self.log_dir.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(access_path.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(app_path.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
