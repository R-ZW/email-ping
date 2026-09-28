import sqlite3
from datetime import datetime
from urllib.parse import urlencode
from zoneinfo import ZoneInfo
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import auth
from app.config import BASE_DIR, PUBLIC_BASE_URL
from app.db import connection_dependency
from app.logging_config import audit_event
from app.routers import emails
from app.routers import tokens as token_routes
from app.routers.security import guard
from app.services import token_status
from app.services.emails_view import list_emails_for_token
from app.services.opens_view import list_opens_for_token
from app.services import smtp_credentials

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
PER_PAGE_OPTIONS = (10, 25, 50, 100)


def human_datetime(value: str | None) -> str:
    if not value:
        return "—"
    try:
        moment = datetime.fromisoformat(value).astimezone(ZoneInfo("America/Sao_Paulo"))
    except ValueError:
        return value
    today = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    if moment.date() == today:
        return f"Hoje às {moment:%H:%M}"
    if (today - moment.date()).days == 1:
        return f"Ontem às {moment:%H:%M}"
    return moment.strftime("%d/%m/%Y às %H:%M")


templates.env.filters["human_datetime"] = human_datetime


def ctx(request, user, **values):
    return {"current_user": user, "csrf_token": auth.csrf_token(request), **values}


def account_response(request, user, conn, *, error: str | None = None, username: str | None = None, smtp_email: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request,
        "account.html",
        ctx(
            request,
            user,
            personal_smtp_email=smtp_email if smtp_email is not None else smtp_credentials.get_personal_email(conn, user.id),
            account_username=username if username is not None else user.username,
            error=error,
        ),
        status_code=status_code,
    )


def audit(request, user, event, action, token):
    audit_event(event, actor=user.username, actor_role=user.role,
                client_ip=request.client.host if request.client else None, action=action,
                target_type="token", target_id=token,
                request_id=getattr(request.state, "request_id", None))


def token_for_user(request, user, conn, token, manage=False):
    try: row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc: raise HTTPException(404, str(exc)) from exc
    if manage: auth.authorize_token_management(request, user, row)
    elif not (user.can_manage_all_tokens or user.id == row.owner_user_id): raise HTTPException(403, "Sem permissão para visualizar este token.")
    return row


@router.get("/", response_class=HTMLResponse)
def ui_tokens_list(request: Request, conn: sqlite3.Connection = Depends(connection_dependency)):
    user = guard(request)
    if isinstance(user, RedirectResponse): return user
    search = request.query_params.get("q", "").strip()[:100]
    usage_status = request.query_params.get("status", "")
    if usage_status not in {"", "unused", "sent", "external"}:
        usage_status = ""
    try: per_page = int(request.query_params.get("per_page", "25"))
    except ValueError: per_page = 25
    if per_page not in PER_PAGE_OPTIONS: per_page = 25
    try: page = max(1, int(request.query_params.get("page", "1")))
    except ValueError: page = 1
    owner_id = None if user.can_manage_all_tokens else user.id
    total = token_status.count_tokens(conn, owner_id, search=search or None, usage_status=usage_status or None)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    rows = token_status.list_tokens(conn, owner_id, search=search or None, usage_status=usage_status or None, limit=per_page, offset=(page - 1) * per_page)
    query_base = urlencode({"q": search, "status": usage_status, "per_page": per_page})
    page_numbers = range(max(1, page - 2), min(total_pages, page + 2) + 1)
    return templates.TemplateResponse(request, "tokens_list.html", ctx(request, user, tokens=rows, search=search, selected_status=usage_status, per_page=per_page, per_page_options=PER_PAGE_OPTIONS, page=page, total_pages=total_pages, total=total, query_base=query_base, page_numbers=page_numbers))


@router.get("/ui/account", response_class=HTMLResponse)
def account_page(request: Request, conn: sqlite3.Connection = Depends(connection_dependency)):
    user = guard(request)
    if isinstance(user, RedirectResponse):
        return user
    return account_response(request, user, conn)


@router.post("/ui/account")
def update_account(
    request: Request,
    username: str = Form(...),
    smtp_email: str = Form(""),
    smtp_app_password: str = Form(""),
    remove_smtp: str | None = Form(None),
    csrf_token: str = Form(...),
    conn: sqlite3.Connection = Depends(connection_dependency),
):
    user = guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    clean_email = smtp_email.strip()
    try:
        updated_user = auth.update_own_username(conn, user.id, username)
        event = "account_updated"
        if remove_smtp == "on":
            if smtp_credentials.remove_personal_settings(conn, user.id):
                event = "personal_smtp_removed"
        elif clean_email:
            current_email = smtp_credentials.get_personal_email(conn, user.id)
            password = smtp_app_password if smtp_app_password else ""
            if not password and current_email != clean_email:
                raise HTTPException(status_code=400, detail="Informe a senha de app para este e-mail.")
            if password:
                smtp_credentials.save_personal_settings(conn, user.id, clean_email, password)
                event = "personal_smtp_updated"
            elif current_email is None:
                raise HTTPException(status_code=400, detail="Informe a senha de app do remetente.")
        conn.commit()
    except smtp_credentials.SMTPCredentialsConfigurationError as exc:
        conn.rollback()
        return account_response(request, user, conn, error=str(exc), username=username.strip(), smtp_email=clean_email, status_code=400)
    except HTTPException as exc:
        conn.rollback()
        return account_response(request, user, conn, error=str(exc.detail), username=username.strip(), smtp_email=clean_email, status_code=exc.status_code)
    request.state.authenticated_user = updated_user.username
    audit_event(event, actor=updated_user.username, actor_role=updated_user.role,
                client_ip=request.client.host if request.client else None, action="update_account",
                target_type="user", target_id=updated_user.id,
                request_id=getattr(request.state, "request_id", None))
    return RedirectResponse("/ui/account", 303)


@router.post("/ui/account/password")
def update_own_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    password_confirmation: str = Form(...),
    csrf_token: str = Form(...),
    conn: sqlite3.Connection = Depends(connection_dependency),
):
    user = guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    if new_password != password_confirmation:
        return account_response(request, user, conn, error="A confirmação da nova senha não coincide.", status_code=400)
    try:
        auth.update_password(conn, user.id, new_password, current_password=current_password)
        conn.commit()
    except HTTPException as exc:
        conn.rollback()
        return account_response(request, user, conn, error=str(exc.detail), status_code=exc.status_code)
    request.session.clear()
    audit_event("password_changed", actor=user.username, actor_role=user.role,
                client_ip=request.client.host if request.client else None, action="change_own_password",
                target_type="user", target_id=user.id,
                request_id=getattr(request.state, "request_id", None))
    return RedirectResponse("/login", 303)


@router.get("/ui/tokens/{token}", response_class=HTMLResponse)
def ui_token_detail(token: str, request: Request, conn: sqlite3.Connection = Depends(connection_dependency)):
    user = guard(request)
    if isinstance(user, RedirectResponse): return user
    row = token_for_user(request, user, conn, token)
    public_url = f"{PUBLIC_BASE_URL}/public/tokens/{row.public_token}" if row.public_link_active and row.public_token else None
    owners = conn.execute("SELECT id,username FROM users WHERE is_active=1 ORDER BY username").fetchall() if user.role == "admin" else []
    return templates.TemplateResponse(request, "token_detail.html", ctx(request, user, token_row=row, usage_status=token_status.get_usage_status(conn,row), opens=list_opens_for_token(conn,row), emails=list_emails_for_token(conn,row.id), can_manage=auth.can_manage_token(user,row.owner_user_id), public_url=public_url, owners=owners))


@router.post("/ui/tokens/{token}/edit")
def ui_edit(token: str, request: Request, name: str = Form(...), recipient_email: str = Form(""), alert_email: str = Form(""), owner_user_id: int | None = Form(None), csrf_token: str = Form(...), conn: sqlite3.Connection = Depends(connection_dependency)):
    user = guard(request)
    if isinstance(user, RedirectResponse): return user
    auth.verify_csrf(request, csrf_token)
    row = token_for_user(request, user, conn, token, True)
    token_routes.update_token_record(conn, user, row, name, recipient_email or None, alert_email or None, owner_user_id)
    audit(request, user, "token_edited", "edit", token)
    return RedirectResponse(f"/ui/tokens/{token}", 303)


@router.post("/ui/tokens/{token}/public-link/{operation}")
def ui_public_link(token:str,operation:str,request:Request,csrf_token:str=Form(...),conn:sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user,RedirectResponse): return user
    auth.verify_csrf(request,csrf_token); row=token_for_user(request,user,conn,token,True)
    if operation == "regenerate": conn.execute("UPDATE tokens SET public_token=?, public_link_active=1 WHERE id=?", (auth.new_public_token(),row.id))
    elif operation == "revoke": conn.execute("UPDATE tokens SET public_link_active=0 WHERE id=?", (row.id,))
    else: raise HTTPException(404,"Operação inexistente.")
    conn.commit(); audit(request, user, f"public_link_{operation}", operation, token); return RedirectResponse(f"/ui/tokens/{token}",303)


@router.post("/ui/tokens/{token}/delete")
def ui_delete(token: str, request: Request, csrf_token: str = Form(...), conn: sqlite3.Connection = Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user, RedirectResponse): return user
    auth.verify_csrf(request, csrf_token); row=token_for_user(request,user,conn,token,True); token_routes.delete_token_record(conn,row); audit(request,user,"token_deleted","delete",token)
    return RedirectResponse("/",303)


@router.get("/ui/new", response_class=HTMLResponse)
def ui_new(request: Request, conn: sqlite3.Connection = Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user, RedirectResponse): return user
    owners=conn.execute("SELECT id,username FROM users WHERE is_active=1 ORDER BY username").fetchall() if user.role == "admin" else []
    return templates.TemplateResponse(request,"new_token.html",ctx(request,user,owners=owners))


@router.post("/ui/new")
def ui_create(request: Request, name: str=Form(...), recipient_email: str=Form(""), alert_email: str=Form(""), owner_user_id: int|None=Form(None), csrf_token: str=Form(...), conn: sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user, RedirectResponse): return user
    auth.verify_csrf(request,csrf_token); row=token_routes.create_token_record(conn,user,name,recipient_email or None,alert_email or None,owner_user_id); audit(request,user,"token_created","create",row["token"])
    return RedirectResponse(f"/ui/tokens/{row['token']}",303)


@router.post("/ui/tokens/{token}/mark_external")
def ui_mark(token:str,request:Request,note:str=Form(""),csrf_token:str=Form(...),conn:sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user,RedirectResponse): return user
    auth.verify_csrf(request,csrf_token); row=token_for_user(request,user,conn,token,True); token_routes.mark_external_record(conn,row,note or None); audit(request,user,"token_marked_external","mark_external",token)
    return RedirectResponse(f"/ui/tokens/{token}",303)


@router.post("/ui/tokens/{token}/confirm")
def ui_confirm(token:str,request:Request,csrf_token:str=Form(...),conn:sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user,RedirectResponse): return user
    auth.verify_csrf(request,csrf_token); token_for_user(request,user,conn,token,True)
    emails.confirm_open(token=token,request=request,actor=user,conn=conn)
    return RedirectResponse(f"/ui/tokens/{token}",303)


@router.post("/ui/tokens/{token}/unmark_external")
def ui_unmark(token:str,request:Request,csrf_token:str=Form(...),conn:sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user,RedirectResponse): return user
    auth.verify_csrf(request,csrf_token); row=token_for_user(request,user,conn,token,True); token_routes.unmark_external_record(conn,row); audit(request,user,"token_unmarked_external","unmark_external",token)
    return RedirectResponse(f"/ui/tokens/{token}",303)


@router.get("/ui/send/{token}", response_class=HTMLResponse)
def ui_send_form(token:str,request:Request,conn:sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user,RedirectResponse): return user
    row=token_for_user(request,user,conn,token,True)
    try: token_status.ensure_can_send(conn,row); blocked_reason=None
    except token_status.TokenAlreadyUsedError as exc: blocked_reason=exc.detail
    return templates.TemplateResponse(request,"send_email_editor.html",ctx(request,user,token_row=row,blocked_reason=blocked_reason))


@router.post("/ui/send/{token}")
def ui_send(token:str,request:Request,subject:str=Form(...),body_html:str=Form(...),files:list[UploadFile]=File(default=[]),csrf_token:str=Form(...),conn:sqlite3.Connection=Depends(connection_dependency)):
    user=guard(request)
    if isinstance(user,RedirectResponse): return user
    auth.verify_csrf(request,csrf_token); token_for_user(request,user,conn,token,True)
    emails.send_email(token=token,request=request,actor=user,subject=subject,body_html=body_html,files=files,conn=conn)
    return RedirectResponse(f"/ui/tokens/{token}",303)
