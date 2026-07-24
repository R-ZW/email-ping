import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.db import get_connection
from app.schemas import EmailOut, OpenOut, OpensListOut
from app.services import mailer, token_status
from app.services.attachments import save_attachments
from app.services.opens_view import list_opens_for_token

router = APIRouter(tags=["emails"])


@router.post("/send_email", response_model=EmailOut)
def send_email(
    token: str = Form(...),
    subject: str = Form(...),
    body_html: str = Form(...),
    files: list[UploadFile] = File(default=[]),
    conn: sqlite3.Connection = Depends(get_connection),
):
    """Envia um email para o destinatário do token, injetando o pixel automaticamente.

    Usado tanto pelo editor de teste na UI quanto por qualquer automação externa
    que já tenha um token criado via /create. Só permite um envio bem-sucedido
    por token (ver token_status.ensure_can_send).
    """
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        token_status.ensure_can_send(conn, token_row)
    except token_status.TokenAlreadyUsedError as exc:
        raise HTTPException(status_code=409, detail=exc.detail) from exc

    if not token_row.recipient_email:
        raise HTTPException(
            status_code=400,
            detail=f"Token '{token}' não tem recipient_email cadastrado; não é possível enviar.",
        )

    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """
        INSERT INTO emails(token_id, subject, body_html, status, created_at)
        VALUES (?, ?, ?, 'pending', ?)
        """,
        (token_row.id, subject, body_html, created_at),
    )
    email_id = cursor.lastrowid
    conn.commit()

    real_files = [f for f in files if f.filename]
    saved_attachments = save_attachments(email_id, real_files) if real_files else []

    for attachment in saved_attachments:
        conn.execute(
            """
            INSERT INTO attachments(email_id, filename, file_path, content_type, size_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                email_id,
                attachment.filename,
                str(attachment.file_path),
                attachment.content_type,
                attachment.size_bytes,
            ),
        )
    conn.commit()

    html_with_pixel = mailer.inject_tracking_pixel(body_html, token)

    try:
        mailer.send_email(
            to_addr=token_row.recipient_email,
            subject=subject,
            html_body=html_with_pixel,
            attachment_paths=[a.file_path for a in saved_attachments],
        )
    except Exception as exc:
        conn.execute(
            "UPDATE emails SET status = 'failed', error_message = ? WHERE id = ?",
            (str(exc), email_id),
        )
        conn.commit()
        raise HTTPException(status_code=502, detail=f"Falha ao enviar email: {exc}") from exc

    sent_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE emails SET status = 'sent', sent_at = ? WHERE id = ?",
        (sent_at, email_id),
    )
    conn.commit()

    row = conn.execute("SELECT * FROM emails WHERE id = ?", (email_id,)).fetchone()
    return EmailOut(
        id=row["id"],
        subject=row["subject"],
        status=row["status"],
        error_message=row["error_message"],
        created_at=row["created_at"],
        sent_at=row["sent_at"],
        attachments=[a.filename for a in saved_attachments],
    )


@router.get("/opens/{token}", response_model=OpensListOut)
def get_opens(token: str, conn: sqlite3.Connection = Depends(get_connection)):
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    opens = [
        OpenOut(
            opened_at=o.opened_at,
            ip=o.ip,
            user_agent=o.user_agent,
            seconds_since_created=o.seconds_since_created,
        )
        for o in list_opens_for_token(conn, token_row)
    ]

    return OpensListOut(token=token, open_count=len(opens), opens=opens)


@router.post("/confirm/{token}")
def confirm_open(token: str, conn: sqlite3.Connection = Depends(get_connection)):
    """Disparo MANUAL da confirmação de leitura. Quem decide se a abertura é
    confiável (não é prefetch de proxy) é o humano, olhando /opens/{token} antes
    de chamar esta rota. Só pode ser confirmado uma vez por token."""
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if token_row.confirmed_at is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Token '{token}' já foi confirmado em {token_row.confirmed_at}.",
        )

    last_open = conn.execute(
        "SELECT opened_at, ip, user_agent FROM opens WHERE token_id = ? ORDER BY opened_at DESC LIMIT 1",
        (token_row.id,),
    ).fetchone()

    if last_open is None:
        raise HTTPException(
            status_code=400,
            detail=f"Token '{token}' ainda não tem nenhuma abertura registrada.",
        )

    confirmed_at = datetime.now(timezone.utc).isoformat()

    try:
        mailer.send_open_confirmation(
            alert_to=token_row.alert_email,
            name=token_row.name,
            token=token,
            opened_at=last_open["opened_at"],
            ip=last_open["ip"],
            user_agent=last_open["user_agent"],
            recipient_email=token_row.recipient_email,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Falha ao enviar confirmação: {exc}") from exc

    conn.execute("UPDATE tokens SET confirmed_at = ? WHERE token = ?", (confirmed_at, token))
    conn.commit()

    return {"token": token, "confirmed_at": confirmed_at}
