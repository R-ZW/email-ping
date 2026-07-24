"""Lógica de listagem de emails (tentativas de envio) de um token, com seus anexos."""

import sqlite3
from dataclasses import dataclass
from typing import Optional


@dataclass
class EmailView:
    id: int
    subject: str
    status: str
    error_message: Optional[str]
    created_at: str
    sent_at: Optional[str]
    attachment_filenames: list[str]


def list_emails_for_token(conn: sqlite3.Connection, token_id: int) -> list[EmailView]:
    email_rows = conn.execute(
        "SELECT * FROM emails WHERE token_id = ? ORDER BY created_at DESC",
        (token_id,),
    ).fetchall()

    result = []
    for row in email_rows:
        attachment_rows = conn.execute(
            "SELECT filename FROM attachments WHERE email_id = ?", (row["id"],)
        ).fetchall()
        result.append(
            EmailView(
                id=row["id"],
                subject=row["subject"],
                status=row["status"],
                error_message=row["error_message"],
                created_at=row["created_at"],
                sent_at=row["sent_at"],
                attachment_filenames=[a["filename"] for a in attachment_rows],
            )
        )
    return result
