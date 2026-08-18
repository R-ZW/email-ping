import sqlite3
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.config import GMAIL_USER
from app.db import get_connection
from app.schemas import MarkExternalRequest, TokenOut
from app.services import token_status

router = APIRouter(tags=["tokens"])


def _row_to_token_out(row: sqlite3.Row, usage_status: str) -> TokenOut:
    return TokenOut(
        token=row["token"],
        name=row["name"],
        recipient_email=row["recipient_email"],
        alert_email=row["alert_email"],
        created_at=row["created_at"],
        confirmed_at=row["confirmed_at"],
        external_use_marked_at=row["external_use_marked_at"],
        external_use_note=row["external_use_note"],
        usage_status=usage_status,
    )


@router.get("/create/{name}", response_model=TokenOut)
def create_tracking(
    name: str,
    recipient_email: Optional[str] = None,
    alert_email: Optional[str] = None,
    conn: sqlite3.Connection = Depends(get_connection),
):
    """Cria um novo token de rastreamento. Não sabe nada sobre conteúdo de email --
    isso é responsabilidade do /send_email, chamado depois (por este sistema ou por
    qualquer automação externa que já tenha um token em mãos)."""
    token = str(uuid.uuid4())
    created_at = datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat()
    resolved_alert_email = alert_email or GMAIL_USER

    if not resolved_alert_email:
        raise HTTPException(
            status_code=400,
            detail="alert_email não informado e GMAIL_USER não está configurado no .env.",
        )

    conn.execute(
        """
        INSERT INTO tokens(token, name, created_at, recipient_email, alert_email)
        VALUES (?, ?, ?, ?, ?)
        """,
        (token, name, created_at, recipient_email, resolved_alert_email),
    )
    conn.commit()

    return TokenOut(
        token=token,
        name=name,
        recipient_email=recipient_email,
        alert_email=resolved_alert_email,
        created_at=created_at,
        confirmed_at=None,
        external_use_marked_at=None,
        external_use_note=None,
        usage_status="unused",
    )


@router.get("/tokens", response_model=list[TokenOut])
def list_tokens(conn: sqlite3.Connection = Depends(get_connection)):
    rows = token_status.list_tokens(conn)
    return [_row_to_token_out(row, row["usage_status"]) for row in rows]


@router.get("/tokens/{token}", response_model=TokenOut)
def get_token(token: str, conn: sqlite3.Connection = Depends(get_connection)):
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    usage_status = token_status.get_usage_status(conn, token_row)
    row = conn.execute("SELECT * FROM tokens WHERE token = ?", (token,)).fetchone()
    return _row_to_token_out(row, usage_status)


@router.post("/tokens/{token}/mark_external", response_model=TokenOut)
def mark_external(
    token: str,
    body: MarkExternalRequest,
    conn: sqlite3.Connection = Depends(get_connection),
):
    """Marca manualmente que este token foi usado por outra forma (fora do /send_email).
    Bloqueia usos futuros de /send_email para este token."""
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if token_status.has_sent_email(conn, token_row.id):
        raise HTTPException(
            status_code=409,
            detail=f"Token '{token}' já teve um email enviado com sucesso via /send_email.",
        )

    marked_at = datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat()
    conn.execute(
        "UPDATE tokens SET external_use_marked_at = ?, external_use_note = ? WHERE token = ?",
        (marked_at, body.note, token),
    )
    conn.commit()

    row = conn.execute("SELECT * FROM tokens WHERE token = ?", (token,)).fetchone()
    return _row_to_token_out(row, "external")


@router.post("/tokens/{token}/unmark_external", response_model=TokenOut)
def unmark_external(token: str, conn: sqlite3.Connection = Depends(get_connection)):
    """Desfaz a marcação de 'usado externamente', caso tenha sido feita por engano."""
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    conn.execute(
        "UPDATE tokens SET external_use_marked_at = NULL, external_use_note = NULL WHERE token = ?",
        (token,),
    )
    conn.commit()

    usage_status = (
        "sent" if token_status.has_sent_email(conn, token_row.id) else "unused"
    )
    row = conn.execute("SELECT * FROM tokens WHERE token = ?", (token,)).fetchone()
    return _row_to_token_out(row, usage_status)
