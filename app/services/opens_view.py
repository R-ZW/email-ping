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
    seconds_since_created: float


def list_opens_for_token(conn: sqlite3.Connection, token_row: TokenRow) -> list[OpenView]:
    rows = conn.execute(
        "SELECT opened_at, ip, user_agent FROM opens WHERE token_id = ? ORDER BY opened_at",
        (token_row.id,),
    ).fetchall()

    created_at_dt = datetime.fromisoformat(token_row.created_at)
    result = []
    for row in rows:
        opened_at_dt = datetime.fromisoformat(row["opened_at"])
        result.append(
            OpenView(
                opened_at=row["opened_at"],
                ip=row["ip"],
                user_agent=row["user_agent"],
                seconds_since_created=(opened_at_dt - created_at_dt).total_seconds(),
            )
        )
    return result
