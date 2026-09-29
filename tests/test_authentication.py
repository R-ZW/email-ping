"""Testes de integração dos limites de autenticação e propriedade."""

from __future__ import annotations

import asyncio
import importlib
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet
from pwdlib import PasswordHash


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="email-ping-auth-"))
        self.database = self.temp_dir / "tracking.db"
        os.environ.update({
            "DATABASE_PATH": str(self.database),
            "LOG_DIR": str(self.temp_dir / "logs"),
            "SESSION_SECRET": "test-session-secret-with-more-than-thirty-two-characters",
            "SESSION_COOKIE_SECURE": "false",
            "SESSION_MAX_AGE_SECONDS": "3600",
            "BOOTSTRAP_ADMIN_USERNAME": "admin",
            "BOOTSTRAP_ADMIN_PASSWORD_HASH": PasswordHash.recommended().hash("admin-password"),
            "GMAIL_USER": "alerts@example.test",
            "SMTP_CREDENTIALS_KEY": Fernet.generate_key().decode("ascii"),
        })

        import app.auth as auth
        import app.config as config
        import app.db as db
        import app.logging_config as logging_config
        import app.main as main
        import app.routers.emails as emails
        import app.routers.security as security
        import app.routers.tokens as tokens
        import app.routers.ui as ui
        import app.services.mailer as mailer
        import app.services.smtp_credentials as smtp_credentials

        self.config = importlib.reload(config)
        self.db = importlib.reload(db)
        self.logging_config = importlib.reload(logging_config)
        self.auth = importlib.reload(auth)
        self.smtp_credentials = importlib.reload(smtp_credentials)
        importlib.reload(mailer)
        importlib.reload(tokens)
        importlib.reload(emails)
        importlib.reload(security)
        importlib.reload(ui)
        self.main = importlib.reload(main)
        self.logging_config.reset_logging_for_tests()
        self.logging_config.configure_logging(force=True)
        self.main.on_startup()

    def tearDown(self):
        self.logging_config.reset_logging_for_tests()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def client(self):
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.main.app), base_url="http://testserver"
        )

    async def login(self, client, username="admin", password="admin-password"):
        return await client.post("/login", data={"username": username, "password": password}, follow_redirects=False)

    async def csrf(self, client):
        page = await client.get("/")
        match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def issue_api(self, username: str) -> str:
        conn = self.db.get_connection()
        try:
            row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        finally:
            conn.close()
        return self.auth.issue_api_token(row["id"], "test")[1]

    def test_login_logout_csrf_and_inactive_user(self):
        async def scenario():
            async with self.client() as client:
                failed = await self.login(client, password="wrong")
                self.assertEqual(failed.status_code, 401)
                success = await self.login(client)
                self.assertEqual(success.status_code, 303)
                self.assertEqual((await client.get("/")).status_code, 200)
                denied_csrf = await client.post("/logout", data={"csrf_token": "wrong"}, follow_redirects=False)
                self.assertEqual(denied_csrf.status_code, 403)
                token = await self.csrf(client)
                logout = await client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
                self.assertEqual(logout.status_code, 303)
                self.assertEqual((await client.get("/", follow_redirects=False)).status_code, 303)

            self.auth.create_user("inactive", "password", "operador")
            self.auth.update_user(self.user_id("inactive"), "operador", False)
            async with self.client() as client:
                self.assertEqual((await self.login(client, "inactive", "password")).status_code, 401)

            self.auth.create_user("session-user", "password", "operador")
            async with self.client() as client:
                self.assertEqual((await self.login(client, "session-user", "password")).status_code, 303)
                self.assertEqual((await client.get("/")).status_code, 200)
                self.auth.update_user(self.user_id("session-user"), "tecnico", True)
                self.assertEqual((await client.get("/", follow_redirects=False)).status_code, 303)

        asyncio.run(scenario())

    def test_account_can_update_name_and_personal_smtp_settings(self):
        self.auth.create_user("sender", "password", "operador")

        async def scenario():
            async with self.client() as client:
                self.assertEqual((await self.login(client, "sender", "password")).status_code, 303)
                account = await client.get("/ui/account")
                self.assertEqual(account.status_code, 200)
                csrf = re.search(r'name="csrf_token" value="([^"]+)"', account.text).group(1)
                saved = await client.post(
                    "/ui/account",
                    data={
                        "csrf_token": csrf,
                        "username": "sender-renamed",
                        "smtp_email": "sender@example.test",
                        "smtp_app_password": "app-password-only-for-test",
                    },
                    follow_redirects=False,
                )
                self.assertEqual(saved.status_code, 303)
                self.assertIn("sender-renamed", (await client.get("/ui/account")).text)

                conn = self.db.get_connection()
                try:
                    user_id = conn.execute("SELECT id FROM users WHERE username='sender-renamed'").fetchone()["id"]
                    cipher = conn.execute("SELECT app_password_cipher FROM user_smtp_settings WHERE user_id=?", (user_id,)).fetchone()["app_password_cipher"]
                    self.assertNotIn("app-password-only-for-test", cipher)
                    settings = self.smtp_credentials.get_personal_settings(conn, user_id)
                    self.assertEqual(settings.email, "sender@example.test")
                    self.assertEqual(settings.app_password, "app-password-only-for-test")
                finally:
                    conn.close()

                csrf = re.search(r'name="csrf_token" value="([^"]+)"', (await client.get("/ui/account")).text).group(1)
                removed = await client.post(
                    "/ui/account",
                    data={"csrf_token": csrf, "username": "sender-renamed", "remove_smtp": "on"},
                    follow_redirects=False,
                )
                self.assertEqual(removed.status_code, 303)

            conn = self.db.get_connection()
            try:
                self.assertIsNone(conn.execute("SELECT 1 FROM user_smtp_settings WHERE user_id=?", (self.user_id("sender-renamed"),)).fetchone())
            finally:
                conn.close()

        asyncio.run(scenario())

    def test_users_can_change_password_and_admin_can_reset_it(self):
        self.auth.create_user("password-user", "old-password", "operador")

        async def scenario():
            async with self.client() as client:
                self.assertEqual((await self.login(client, "password-user", "old-password")).status_code, 303)
                account = await client.get("/ui/account")
                csrf = re.search(r'name="csrf_token" value="([^"]+)"', account.text).group(1)
                denied = await client.post(
                    "/ui/account/password",
                    data={"csrf_token": csrf, "current_password": "incorrect", "new_password": "new-password", "password_confirmation": "new-password"},
                )
                self.assertEqual(denied.status_code, 400)
                changed = await client.post(
                    "/ui/account/password",
                    data={"csrf_token": csrf, "current_password": "old-password", "new_password": "new-password", "password_confirmation": "new-password"},
                    follow_redirects=False,
                )
                self.assertEqual(changed.status_code, 303)
                self.assertEqual((await self.login(client, "password-user", "old-password")).status_code, 401)
                self.assertEqual((await self.login(client, "password-user", "new-password")).status_code, 303)

            async with self.client() as admin_client:
                self.assertEqual((await self.login(admin_client)).status_code, 303)
                csrf = await self.csrf(admin_client)
                reset = await admin_client.post(
                    f"/ui/users/{self.user_id('password-user')}/password",
                    data={"csrf_token": csrf, "new_password": "admin-reset-password", "password_confirmation": "admin-reset-password"},
                    follow_redirects=False,
                )
                self.assertEqual(reset.status_code, 303)

            async with self.client() as user_client:
                self.assertEqual((await self.login(user_client, "password-user", "new-password")).status_code, 401)
                self.assertEqual((await self.login(user_client, "password-user", "admin-reset-password")).status_code, 303)

        asyncio.run(scenario())

    def user_id(self, username: str) -> int:
        conn = self.db.get_connection()
        try:
            return conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        finally:
            conn.close()

    def test_public_link_is_read_only_safe_and_revocable(self):
        async def scenario():
            bearer = self.issue_api("admin")
            headers = {"Authorization": f"Bearer {bearer}"}
            async with self.client() as client:
                created = await client.post("/tokens", headers=headers, json={
                    "name": "Registro público", "recipient_email": "recipient@example.test", "alert_email": "alert@example.test",
                })
                self.assertEqual(created.status_code, 201)
                item = created.json()
                public_path = urlsplit(item["public_url"]).path
                guest = await client.get(public_path)
                self.assertEqual(guest.status_code, 200)
                self.assertEqual(guest.headers["cache-control"], "no-store")
                self.assertEqual(guest.headers["referrer-policy"], "no-referrer")
                self.assertEqual(guest.headers["x-robots-tag"], "noindex, nofollow")
                for secret in (item["token"], "recipient@example.test", "alert@example.test"):
                    self.assertNotIn(secret, guest.text)
                self.assertNotIn("<form", guest.text.lower())
                self.assertNotIn("/ui/", guest.text)
                self.assertEqual((await client.get("/tokens")).status_code, 401)
                regenerated = await client.post(f"/tokens/{item['token']}/public-link/regenerate", headers=headers)
                self.assertEqual(regenerated.status_code, 200)
                self.assertEqual((await client.get(public_path)).status_code, 404)
                self.assertEqual((await client.get(urlsplit(regenerated.json()["public_url"]).path)).status_code, 200)
            log_text = "".join(path.read_text(encoding="utf-8") for path in (self.temp_dir / "logs").glob("*.log"))
            self.assertNotIn(public_path.rsplit("/", 1)[-1], log_text)
            self.assertNotIn(bearer, log_text)
        asyncio.run(scenario())

    def test_bearer_owner_boundaries_and_revocation(self):
        self.auth.create_user("operator-a", "password", "operador")
        self.auth.create_user("operator-b", "password", "operador")
        self.auth.create_user("tech", "password", "tecnico")

        async def scenario():
            admin_key = self.issue_api("admin")
            a_key = self.issue_api("operator-a")
            b_key = self.issue_api("operator-b")
            tech_key = self.issue_api("tech")
            async with self.client() as client:
                a = await client.post("/tokens", headers={"Authorization": f"Bearer {a_key}"}, json={
                    "name": "A", "owner_user_id": self.user_id("operator-b")
                })
                self.assertEqual(a.status_code, 201)
                self.assertEqual(a.json()["owner_username"], "operator-a")
                b = await client.post("/tokens", headers={"Authorization": f"Bearer {admin_key}"}, json={
                    "name": "B", "owner_user_id": self.user_id("operator-b")
                })
                self.assertEqual(b.status_code, 201)
                tech_created = await client.post("/tokens", headers={"Authorization": f"Bearer {tech_key}"}, json={
                    "name": "Técnico", "owner_user_id": self.user_id("operator-b")
                })
                self.assertEqual(tech_created.status_code, 201)
                self.assertEqual(tech_created.json()["owner_username"], "tech")
                self.assertEqual(tech_created.json()["created_by_username"], "tech")
                own_list = await client.get("/tokens", headers={"Authorization": f"Bearer {a_key}"})
                self.assertEqual([row["name"] for row in own_list.json()], ["A"])
                forbidden = await client.post(f"/tokens/{b.json()['token']}/mark_external", headers={"Authorization": f"Bearer {a_key}"}, json={})
                self.assertEqual(forbidden.status_code, 403)
                tech_allowed = await client.post(f"/tokens/{b.json()['token']}/mark_external", headers={"Authorization": f"Bearer {tech_key}"}, json={})
                self.assertEqual(tech_allowed.status_code, 200)
                self.auth.revoke_api_token(self.api_token_id(b_key))
                self.assertEqual((await client.get("/tokens", headers={"Authorization": f"Bearer {b_key}"})).status_code, 401)

        asyncio.run(scenario())

    def test_admin_and_technician_can_switch_between_own_and_all_tokens_in_ui(self):
        self.auth.create_user("operator", "password", "operador")
        self.auth.create_user("tech", "password", "tecnico")

        async def scenario():
            admin_key = self.issue_api("admin")
            tech_key = self.issue_api("tech")
            async with self.client() as client:
                self.assertEqual(
                    (await client.post("/tokens", headers={"Authorization": f"Bearer {admin_key}"}, json={"name": "Token do admin"})).status_code,
                    201,
                )
                self.assertEqual(
                    (await client.post("/tokens", headers={"Authorization": f"Bearer {admin_key}"}, json={"name": "Token do operador", "owner_user_id": self.user_id("operator")})).status_code,
                    201,
                )
                self.assertEqual(
                    (await client.post("/tokens", headers={"Authorization": f"Bearer {tech_key}"}, json={"name": "Token do técnico"})).status_code,
                    201,
                )

            async with self.client() as admin_client:
                self.assertEqual((await self.login(admin_client)).status_code, 303)
                mine = await admin_client.get("/")
                self.assertIn("Meus tokens", mine.text)
                self.assertIn("Token do admin", mine.text)
                self.assertNotIn("Token do operador", mine.text)
                all_tokens = await admin_client.get("/?scope=all")
                self.assertIn("Token do admin", all_tokens.text)
                self.assertIn("Token do operador", all_tokens.text)
                self.assertIn("Token do técnico", all_tokens.text)

            async with self.client() as tech_client:
                self.assertEqual((await self.login(tech_client, "tech", "password")).status_code, 303)
                mine = await tech_client.get("/")
                self.assertIn("Meus tokens", mine.text)
                self.assertIn("Token do técnico", mine.text)
                self.assertNotIn("Token do admin", mine.text)
                all_tokens = await tech_client.get("/?scope=all")
                self.assertIn("Token do admin", all_tokens.text)
                self.assertIn("Token do operador", all_tokens.text)
                self.assertIn("Token do técnico", all_tokens.text)

        asyncio.run(scenario())

    def api_token_id(self, raw: str) -> int:
        conn = self.db.get_connection()
        try:
            return conn.execute("SELECT id FROM api_tokens WHERE token_hash=?", (self.auth.token_hash(raw),)).fetchone()["id"]
        finally:
            conn.close()

    def test_existing_database_migrates_without_losing_token(self):
        self.logging_config.reset_logging_for_tests()
        self.database.unlink()
        conn = sqlite3.connect(self.database)
        try:
            conn.execute("""CREATE TABLE tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, name TEXT NOT NULL, recipient_email TEXT, alert_email TEXT NOT NULL, created_at TEXT NOT NULL, confirmed_at TEXT, external_use_marked_at TEXT, external_use_note TEXT)""")
            conn.execute("INSERT INTO tokens(token,name,alert_email,created_at) VALUES ('legacy-token','Legado','alert@example.test','2026-01-01')")
            conn.commit()
        finally:
            conn.close()
        self.db.init_db()
        self.auth.bootstrap_admin_and_migrate_tokens()
        conn = self.db.get_connection()
        try:
            legacy = conn.execute("SELECT owner_user_id,created_by_user_id,public_token,public_link_active FROM tokens WHERE token='legacy-token'").fetchone()
            admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
            self.assertEqual(legacy["owner_user_id"], admin["id"])
            self.assertEqual(legacy["created_by_user_id"], admin["id"])
            self.assertTrue(legacy["public_token"])
            self.assertEqual(legacy["public_link_active"], 1)
        finally:
            conn.close()

