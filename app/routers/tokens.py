import sqlite3
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth import CurrentUser, authorize_token_management, new_public_token, require_api_user
from app.config import GMAIL_USER, PUBLIC_BASE_URL
from app.db import connection_dependency
from app.logging_config import audit_event
from app.schemas import CreateTokenRequest, MarkExternalRequest, TokenOut, UpdateTokenRequest
from app.services import token_status

router = APIRouter(tags=["tokens"])


def _find(conn, token):
    try:
        return token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc


def _row(conn, token_id):
    return conn.execute("SELECT t.*, u.username AS owner_username FROM tokens t LEFT JOIN users u ON u.id=t.owner_user_id WHERE t.id=?", (token_id,)).fetchone()


def token_out(row, usage_status):
    public_url = f"{PUBLIC_BASE_URL}/public/tokens/{row['public_token']}" if row["public_link_active"] and row["public_token"] else None
    return TokenOut(token=row["token"], name=row["name"], recipient_email=row["recipient_email"], alert_email=row["alert_email"], created_at=row["created_at"], confirmed_at=row["confirmed_at"], external_use_marked_at=row["external_use_marked_at"], external_use_note=row["external_use_note"], usage_status=usage_status, owner_username=row["owner_username"], public_url=public_url)


def create_token_record(conn, actor, name, recipient_email, alert_email, owner_user_id=None):
    owner_id = actor.id if actor.role == "operador" else (owner_user_id or actor.id)
    if conn.execute("SELECT 1 FROM users WHERE id=? AND is_active=1", (owner_id,)).fetchone() is None:
        raise HTTPException(400, "Proprietário inválido ou inativo.")
    alert = alert_email or GMAIL_USER
    if not alert:
        raise HTTPException(400, "alert_email não informado e GMAIL_USER não está configurado.")
    cursor = conn.execute("INSERT INTO tokens(token,name,recipient_email,alert_email,created_at,owner_user_id,public_token,public_link_active) VALUES (?,?,?,?,?,?,?,1)", (str(uuid.uuid4()), name, recipient_email, alert, datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(), owner_id, new_public_token()))
    conn.commit()
    return _row(conn, cursor.lastrowid)


def mark_external_record(conn, token_row, note):
    if token_status.has_sent_email(conn, token_row.id):
        raise HTTPException(409, "Token já teve um email enviado com sucesso.")
    conn.execute("UPDATE tokens SET external_use_marked_at=?, external_use_note=? WHERE id=?", (datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(), note, token_row.id))
    conn.commit()
    return _row(conn, token_row.id)


def unmark_external_record(conn, token_row):
    conn.execute("UPDATE tokens SET external_use_marked_at=NULL, external_use_note=NULL WHERE id=?", (token_row.id,))
    conn.commit()
    return _row(conn, token_row.id)


def delete_token_record(conn, token_row):
    conn.execute("DELETE FROM tokens WHERE id=?", (token_row.id,))
    conn.commit()


def update_token_record(conn, actor, token_row, name, recipient_email, alert_email, owner_user_id=None):
    owner_id = token_row.owner_user_id
    if actor.can_manage_all_tokens and owner_user_id is not None:
        owner_id = owner_user_id
    if conn.execute("SELECT 1 FROM users WHERE id=? AND is_active=1", (owner_id,)).fetchone() is None:
        raise HTTPException(400, "Proprietário inválido ou inativo.")
    alert = alert_email or token_row.alert_email
    if not alert:
        raise HTTPException(400, "alert_email é obrigatório.")
    conn.execute("UPDATE tokens SET name=?,recipient_email=?,alert_email=?,owner_user_id=? WHERE id=?", (name,recipient_email,alert,owner_id,token_row.id))
    conn.commit()
    return _row(conn, token_row.id)


def _view(request, actor, token_row):
    if actor.can_manage_all_tokens or actor.id == token_row.owner_user_id:
        return
    audit_event("authorization_denied", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action="view_token", target_type="token", target_id=token_row.token, outcome="denied", request_id=getattr(request.state, "request_id", None))
    raise HTTPException(403, "Sem permissão para visualizar este token.")


@router.post("/tokens", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def create_tracking(body: CreateTokenRequest, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    row = create_token_record(conn, actor, body.name, body.recipient_email, body.alert_email, body.owner_user_id)
    audit_event("token_created", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action="create", target_type="token", target_id=row["token"], request_id=getattr(request.state, "request_id", None))
    return token_out(row, "unused")


@router.get("/tokens", response_model=list[TokenOut])
def list_tokens(request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    rows = token_status.list_tokens(conn, None if actor.can_manage_all_tokens else actor.id)
    return [token_out(row, row["usage_status"]) for row in rows]


@router.get("/tokens/{token}", response_model=TokenOut)
def get_token(token: str, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    token_row = _find(conn, token)
    _view(request, actor, token_row)
    return token_out(_row(conn, token_row.id), token_status.get_usage_status(conn, token_row))


@router.post("/tokens/{token}/edit", response_model=TokenOut)
def edit_token(token: str, body: UpdateTokenRequest, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    token_row = _find(conn, token)
    authorize_token_management(request, actor, token_row)
    row = update_token_record(conn, actor, token_row, body.name, body.recipient_email, body.alert_email, body.owner_user_id)
    audit_event("token_edited", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action="edit", target_type="token", target_id=token, request_id=getattr(request.state, "request_id", None))
    return token_out(row, token_status.get_usage_status(conn, row))


@router.post("/tokens/{token}/mark_external", response_model=TokenOut)
def mark_external(token: str, body: MarkExternalRequest, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    token_row = _find(conn, token); authorize_token_management(request, actor, token_row)
    row = mark_external_record(conn, token_row, body.note)
    audit_event("token_marked_external", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action="mark_external", target_type="token", target_id=token, request_id=getattr(request.state, "request_id", None))
    return token_out(row, "external")


@router.post("/tokens/{token}/unmark_external", response_model=TokenOut)
def unmark_external(token: str, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    token_row = _find(conn, token); authorize_token_management(request, actor, token_row)
    row = unmark_external_record(conn, token_row)
    audit_event("token_unmarked_external", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action="unmark_external", target_type="token", target_id=token, request_id=getattr(request.state, "request_id", None))
    return token_out(row, token_status.get_usage_status(conn, token_row))


@router.post("/tokens/{token}/public-link/{operation}", response_model=TokenOut)
def public_link(token: str, operation: str, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    token_row = _find(conn, token); authorize_token_management(request, actor, token_row)
    if operation == "regenerate":
        conn.execute("UPDATE tokens SET public_token=?, public_link_active=1 WHERE id=?", (new_public_token(), token_row.id))
    elif operation == "revoke":
        conn.execute("UPDATE tokens SET public_link_active=0 WHERE id=?", (token_row.id,))
    else:
        raise HTTPException(404, "Operação inexistente.")
    conn.commit()
    audit_event(f"public_link_{operation}", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action=operation, target_type="token", target_id=token, request_id=getattr(request.state, "request_id", None))
    return token_out(_row(conn, token_row.id), token_status.get_usage_status(conn, token_row))


@router.post("/tokens/{token}", status_code=status.HTTP_204_NO_CONTENT)
def delete_token(token: str, request: Request, actor: CurrentUser = Depends(require_api_user), conn: sqlite3.Connection = Depends(connection_dependency)):
    token_row = _find(conn, token); authorize_token_management(request, actor, token_row)
    delete_token_record(conn, token_row)
    audit_event("token_deleted", actor=actor.username, actor_role=actor.role, client_ip=request.client.host if request.client else None, action="delete", target_type="token", target_id=token, request_id=getattr(request.state, "request_id", None))
