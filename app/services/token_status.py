"""
Regras sobre o "status de uso" de um token.

Um token pode estar em 3 estados (calculados, não armazenados diretamente):
- unused:   nunca foi enviado com sucesso nem marcado como usado externamente
- sent:     existe um email com status='sent' vinculado a esse token
- external: o usuário marcou manualmente como "usado por outra forma"

'external' tem precedência sobre 'sent' na leitura porque, na prática, se o
usuário marcou manualmente é porque quer que esse token pare de ser usado
pelo /send_email -- ver TokenAlreadyUsedError abaixo.
"""

import sqlite3
from dataclasses import dataclass
from typing import Optional


class TokenNotFoundError(Exception):
    pass


class TokenAlreadyUsedError(Exception):
    """Levantado quando /send_email é chamado para um token que já foi usado
    (seja via envio bem-sucedido anterior, seja marcado como usado externamente)."""

    def __init__(self, usage_status: str, detail: str):
        self.usage_status = usage_status
        self.detail = detail
        super().__init__(detail)


@dataclass
class TokenRow:
    id: int
    token: str
    name: str
    recipient_email: Optional[str]
    alert_email: str
    created_at: str
    confirmed_at: Optional[str]
    external_use_marked_at: Optional[str]
    external_use_note: Optional[str]


def get_token_or_raise(conn: sqlite3.Connection, token: str) -> TokenRow:
    row = conn.execute("SELECT * FROM tokens WHERE token = ?", (token,)).fetchone()
    if row is None:
        raise TokenNotFoundError(f"Token '{token}' não existe.")
    return TokenRow(
        id=row["id"],
        token=row["token"],
        name=row["name"],
        recipient_email=row["recipient_email"],
        alert_email=row["alert_email"],
        created_at=row["created_at"],
        confirmed_at=row["confirmed_at"],
        external_use_marked_at=row["external_use_marked_at"],
        external_use_note=row["external_use_note"],
    )


def has_sent_email(conn: sqlite3.Connection, token_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM emails WHERE token_id = ? AND status = 'sent' LIMIT 1",
        (token_id,),
    ).fetchone()
    return row is not None


def get_usage_status(conn: sqlite3.Connection, token_row: TokenRow) -> str:
    if token_row.external_use_marked_at is not None:
        return "external"
    if has_sent_email(conn, token_row.id):
        return "sent"
    return "unused"


def list_tokens(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Lista todos os tokens com o usage_status já calculado via SQL (sem N+1 queries)."""
    query = """
        SELECT
            t.*,
            CASE
                WHEN t.external_use_marked_at IS NOT NULL THEN 'external'
                WHEN EXISTS (
                    SELECT 1 FROM emails e WHERE e.token_id = t.id AND e.status = 'sent'
                ) THEN 'sent'
                ELSE 'unused'
            END AS usage_status
        FROM tokens t
        ORDER BY t.created_at DESC
    """
    return conn.execute(query).fetchall()


def ensure_can_send(conn: sqlite3.Connection, token_row: TokenRow) -> None:
    """Levanta TokenAlreadyUsedError se este token não puder mais ser usado em /send_email."""
    status = get_usage_status(conn, token_row)
    if status == "sent":
        raise TokenAlreadyUsedError(
            status, f"Token '{token_row.token}' já teve um email enviado com sucesso."
        )
    if status == "external":
        raise TokenAlreadyUsedError(
            status,
            f"Token '{token_row.token}' foi marcado como usado por outra forma "
            f"({token_row.external_use_note or 'sem observação'}).",
        )
