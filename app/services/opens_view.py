"""
Lógica de listagem de aberturas, compartilhada entre a rota de API (/opens/{token})
e a página de detalhe da UI -- ambas precisam do mesmo cálculo de "quantos segundos
depois do envio essa abertura aconteceu", usado pelo humano pra julgar se é prefetch
de proxy ou leitura real.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.services.token_status import TokenRow


@dataclass
class OpenView:
    opened_at: str
    ip: Optional[str]
    user_agent: Optional[str]
    seconds_since_sent: float


def list_opens_for_token(
    conn: sqlite3.Connection, token_row: TokenRow
) -> list[OpenView]:
    rows = conn.execute(
        "SELECT opened_at, ip, user_agent FROM opens WHERE token_id = ? ORDER BY opened_at",
        (token_row.id,),
    ).fetchall()

    email = conn.execute(
        "SELECT sent_at FROM emails WHERE token_id = ? ORDER BY sent_at LIMIT 1",
        (token_row.id,),
    ).fetchall()

    created_at_dt = datetime.fromisoformat(token_row.created_at)
    if token_row.external_use_marked_at is not None:
        external_use_marked_at = datetime.fromisoformat(
            token_row.external_use_marked_at
        )
    else:
        external_use_marked_at = None
    sent_at_dt = datetime.fromisoformat(email[0]["sent_at"]) if email else None

    base_dt = sent_at_dt or external_use_marked_at or created_at_dt

    result = []
    for row in rows:
        opened_at_dt = datetime.fromisoformat(row["opened_at"])
        result.append(
            OpenView(
                opened_at=row["opened_at"],
                ip=row["ip"],
                user_agent=row["user_agent"],
                seconds_since_sent=(opened_at_dt - base_dt).total_seconds(),
            )
        )
    return result
