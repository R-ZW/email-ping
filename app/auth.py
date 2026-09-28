"""Usuários, sessão, CSRF e autorização centralizados."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pwdlib import PasswordHash

from app.config import (
    BOOTSTRAP_ADMIN_PASSWORD_HASH,
    BOOTSTRAP_ADMIN_USERNAME,
    SESSION_SECRET,
)
from app.db import get_connection
from app.logging_config import audit_event

Role = Literal["admin", "tecnico", "operador"]
PASSWORD_HASHER = PasswordHash.recommended()
_DUMMY_HASH = PASSWORD_HASHER.hash("dummy-password-that-is-never-used")


@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    role: Role
    is_active: bool
    session_version: int

    @property
    def can_manage_all_tokens(self) -> bool:
        return self.role in {"admin", "tecnico"}


def now_iso() -> str:
    return datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat()


def validate_auth_configuration() -> None:
    if not SESSION_SECRET or len(SESSION_SECRET) < 32:
        raise RuntimeError("SESSION_SECRET ausente ou curto demais (mínimo de 32 caracteres).")


def bootstrap_admin_and_migrate_tokens() -> None:
    """Cria o primeiro admin e atribui dados legados de forma idempotente."""
    validate_auth_configuration()
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            if not BOOTSTRAP_ADMIN_USERNAME or not BOOTSTRAP_ADMIN_PASSWORD_HASH:
                raise RuntimeError(
                    "Defina BOOTSTRAP_ADMIN_USERNAME e BOOTSTRAP_ADMIN_PASSWORD_HASH para criar o primeiro administrador."
                )
            if not BOOTSTRAP_ADMIN_PASSWORD_HASH.startswith("$argon2"):
                raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD_HASH deve ser um hash Argon2.")
            created = now_iso()
            conn.execute(
                """INSERT INTO users(username, password_hash, role, is_active, created_at, updated_at)
                   VALUES (?, ?, 'admin', 1, ?, ?)""",
                (BOOTSTRAP_ADMIN_USERNAME, BOOTSTRAP_ADMIN_PASSWORD_HASH, created, created),
            )

        admin = conn.execute(
            "SELECT * FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
        ).fetchone()
        if admin is None:
            raise RuntimeError("O banco precisa de pelo menos um usuário admin ativo para migrar tokens.")
        conn.execute(
            "UPDATE tokens SET owner_user_id = ? WHERE owner_user_id IS NULL",
            (admin["id"],),
        )
        conn.execute(
            "UPDATE tokens SET created_by_user_id = ? WHERE created_by_user_id IS NULL",
            (admin["id"],),
        )
        rows = conn.execute("SELECT id FROM tokens WHERE public_token IS NULL").fetchall()
        for row in rows:
            conn.execute(
                "UPDATE tokens SET public_token = ?, public_link_active = 1 WHERE id = ?",
                (new_public_token(), row["id"]),
            )
        conn.commit()
    finally:
        conn.close()


def new_public_token() -> str:
    return secrets.token_urlsafe(32)


def new_api_token() -> str:
    return "epat_" + secrets.token_urlsafe(32)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def row_to_user(row: sqlite3.Row) -> CurrentUser:
    return CurrentUser(
        id=row["id"],
        username=row["username"],
        role=row["role"],
        is_active=bool(row["is_active"]),
        session_version=row["session_version"],
    )


def get_user(conn: sqlite3.Connection, user_id: int) -> CurrentUser | None:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return row_to_user(row) if row else None


def authenticate(username: str, password: str) -> CurrentUser | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            PASSWORD_HASHER.verify(password, _DUMMY_HASH)
            return None
        valid = PASSWORD_HASHER.verify(password, row["password_hash"])
        user = row_to_user(row)
        return user if valid and user.is_active else None
    finally:
        conn.close()


def session_user(request: Request) -> CurrentUser | None:
    session = request.session
    user_id = session.get("user_id")
    session_version = session.get("session_version")
    if not isinstance(user_id, int) or not isinstance(session_version, int):
        return None
    conn = get_connection()
    try:
        user = get_user(conn, user_id)
    finally:
        conn.close()
    if not user or not user.is_active or user.session_version != session_version:
        request.session.clear()
        return None
    request.state.authenticated_user = user.username
    return user


def require_ui_user(request: Request) -> CurrentUser:
    user = session_user(request)
    if user:
        return user
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    return RedirectResponse(url=f"/login?next={quote(target, safe='/?=&')}", status_code=303)  # type: ignore[return-value]


def require_api_user(request: Request) -> CurrentUser:
    header = request.headers.get("authorization", "")
    scheme, _, raw_token = header.partition(" ")
    if scheme.lower() != "bearer" or not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token obrigatório.")
    conn = get_connection()
    try:
        digest = token_hash(raw_token)
        row = conn.execute(
            """SELECT a.token_hash AS api_token_hash, u.* FROM api_tokens a JOIN users u ON u.id = a.user_id
               WHERE a.token_hash = ? AND a.revoked_at IS NULL""",
            (digest,),
        ).fetchone()
        if row is None or not hmac.compare_digest(row["api_token_hash"], digest):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token inválido.")
        user = row_to_user(row)
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário inativo.")
        request.state.authenticated_user = user.username
        return user
    finally:
        conn.close()


def require_admin(user: CurrentUser) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso restrito a administradores.")


def require_docs_user(request: Request) -> CurrentUser:
    user = require_ui_user(request)
    if isinstance(user, RedirectResponse):
        return user  # type: ignore[return-value]
    if user.role not in {"admin", "tecnico"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sem permissão para a documentação.")
    return user


def can_manage_token(user: CurrentUser, owner_user_id: int | None) -> bool:
    return user.can_manage_all_tokens or user.id == owner_user_id


def authorize_token_management(request: Request, user: CurrentUser, token_row) -> None:
    if can_manage_token(user, token_row.owner_user_id):
        return
    audit_event(
        "authorization_denied",
        actor=user.username,
        actor_role=user.role,
        client_ip=request.client.host if request.client else None,
        action="manage_token",
        target_type="token",
        target_id=token_row.token,
        outcome="denied",
        request_id=getattr(request.state, "request_id", None),
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sem permissão para gerenciar este token.")


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, supplied: str) -> None:
    expected = request.session.get("csrf_token")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF inválido.")


def create_user(username: str, password: str, role: Role) -> CurrentUser:
    if role not in {"admin", "tecnico", "operador"}:
        raise HTTPException(status_code=400, detail="Função inválida.")
    if not username or len(username) > 80 or not password:
        raise HTTPException(status_code=400, detail="Usuário e senha são obrigatórios.")
    created = now_iso()
    conn = get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO users(username, password_hash, role, is_active, created_at, updated_at)
               VALUES (?, ?, ?, 1, ?, ?)""",
            (username, PASSWORD_HASHER.hash(password), role, created, created),
        )
        conn.commit()
        return get_user(conn, cursor.lastrowid)  # type: ignore[return-value]
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Nome de usuário já existe.") from exc
    finally:
        conn.close()


def issue_api_token(user_id: int, label: str) -> tuple[int, str]:
    raw = new_api_token()
    conn = get_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO api_tokens(user_id, token_hash, label, created_at) VALUES (?, ?, ?, ?)",
            (user_id, token_hash(raw), label or "token", now_iso()),
        )
        conn.commit()
        return cursor.lastrowid, raw
    finally:
        conn.close()


def revoke_api_token(token_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute("UPDATE api_tokens SET revoked_at = ? WHERE id = ?", (now_iso(), token_id))
        conn.commit()
    finally:
        conn.close()


def update_user(user_id: int, role: Role, is_active: bool) -> CurrentUser:
    """Atualiza a conta e invalida imediatamente as sessões já emitidas."""
    if role not in {"admin", "tecnico", "operador"}:
        raise HTTPException(status_code=400, detail="Função inválida.")
    conn = get_connection()
    try:
        current = get_user(conn, user_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")
        if current.role == "admin" and current.is_active and (role != "admin" or not is_active):
            active_admins = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
            ).fetchone()[0]
            if active_admins <= 1:
                raise HTTPException(
                    status_code=409,
                    detail="Não é possível remover ou desativar o último administrador ativo.",
                )
        updated = now_iso()
        conn.execute(
            """UPDATE users
               SET role=?, is_active=?, session_version=session_version+1, updated_at=?
               WHERE id=?""",
            (role, int(is_active), updated, user_id),
        )
        conn.commit()
        return get_user(conn, user_id)  # type: ignore[return-value]
    finally:
        conn.close()


def update_own_username(
    conn: sqlite3.Connection, user_id: int, username: str
) -> CurrentUser:
    """Atualiza somente o nome da própria conta dentro da transação atual."""
    clean_username = username.strip()
    if not clean_username or len(clean_username) > 80:
        raise HTTPException(status_code=400, detail="Informe um nome de usuário de até 80 caracteres.")
    try:
        conn.execute(
            "UPDATE users SET username=?, updated_at=? WHERE id=?",
            (clean_username, now_iso(), user_id),
        )
        user = get_user(conn, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")
        return user
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Nome de usuário já existe.") from exc


def list_api_tokens() -> list[sqlite3.Row]:
    conn = get_connection()
    try:
        return conn.execute(
            """SELECT a.id, a.user_id, a.label, a.created_at, a.revoked_at, u.username
               FROM api_tokens a JOIN users u ON u.id=a.user_id
               ORDER BY a.id DESC"""
        ).fetchall()
    finally:
        conn.close()
