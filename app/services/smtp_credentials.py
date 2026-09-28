"""Credenciais SMTP individuais, armazenadas de forma criptografada."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from email.utils import parseaddr
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

from app.config import SMTP_CREDENTIALS_KEY


class SMTPCredentialsConfigurationError(Exception):
    """A chave necessária para ler as credenciais individuais é inválida."""


@dataclass(frozen=True)
class PersonalSMTPSettings:
    email: str
    app_password: str


def _now_iso() -> str:
    return datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat()


def _cipher() -> Fernet:
    if not SMTP_CREDENTIALS_KEY:
        raise SMTPCredentialsConfigurationError(
            "SMTP_CREDENTIALS_KEY não foi configurada para usar um remetente pessoal."
        )
    try:
        return Fernet(SMTP_CREDENTIALS_KEY.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise SMTPCredentialsConfigurationError(
            "SMTP_CREDENTIALS_KEY é inválida. Gere uma nova chave Fernet."
        ) from exc


def _validate_email(value: str) -> str:
    email = value.strip()
    _, parsed = parseaddr(email)
    if not email or parsed != email or "@" not in email or len(email) > 254:
        raise HTTPException(status_code=400, detail="Informe um e-mail de remetente válido.")
    return email


def get_personal_settings(
    conn: sqlite3.Connection, user_id: int
) -> PersonalSMTPSettings | None:
    row = conn.execute(
        "SELECT smtp_email, app_password_cipher FROM user_smtp_settings WHERE user_id=?",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        password = _cipher().decrypt(row["app_password_cipher"].encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise SMTPCredentialsConfigurationError(
            "Não foi possível ler a configuração do remetente pessoal."
        ) from exc
    return PersonalSMTPSettings(email=row["smtp_email"], app_password=password)


def get_personal_email(conn: sqlite3.Connection, user_id: int) -> str | None:
    row = conn.execute(
        "SELECT smtp_email FROM user_smtp_settings WHERE user_id=?", (user_id,)
    ).fetchone()
    return row["smtp_email"] if row else None


def save_personal_settings(
    conn: sqlite3.Connection,
    user_id: int,
    email: str,
    app_password: str,
) -> None:
    clean_email = _validate_email(email)
    if not app_password:
        raise HTTPException(status_code=400, detail="Informe a senha de app do remetente.")
    encrypted = _cipher().encrypt(app_password.encode("utf-8")).decode("ascii")
    now = _now_iso()
    conn.execute(
        """INSERT INTO user_smtp_settings(user_id,smtp_email,app_password_cipher,created_at,updated_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(user_id) DO UPDATE SET smtp_email=excluded.smtp_email,
               app_password_cipher=excluded.app_password_cipher, updated_at=excluded.updated_at""",
        (user_id, clean_email, encrypted, now, now),
    )


def remove_personal_settings(conn: sqlite3.Connection, user_id: int) -> bool:
    return conn.execute(
        "DELETE FROM user_smtp_settings WHERE user_id=?", (user_id,)
    ).rowcount == 1
