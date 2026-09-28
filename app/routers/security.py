import sqlite3

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import auth
from app.config import BASE_DIR
from app.db import get_connection
from app.logging_config import audit_event

router = APIRouter(tags=["security"])
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def guard(request: Request):
    user = auth.session_user(request)
    if user:
        return user
    return RedirectResponse("/login", status_code=303)


def admin_guard(request: Request):
    user = guard(request)
    if isinstance(user, RedirectResponse):
        return user
    if user.role != "admin":
        audit_event("authorization_denied", actor=user.username, actor_role=user.role,
                    client_ip=client_ip(request), action="manage_users", outcome="denied",
                    request_id=getattr(request.state, "request_id", None))
        raise HTTPException(403, "Acesso restrito a administradores.")
    return user


def docs_guard(request: Request):
    user = guard(request)
    if isinstance(user, RedirectResponse):
        return user
    if user.role not in {"admin", "tecnico"}:
        audit_event("authorization_denied", actor=user.username, actor_role=user.role,
                    client_ip=client_ip(request), action="api_docs", outcome="denied",
                    request_id=getattr(request.state, "request_id", None))
        raise HTTPException(403, "Sem permissão para a documentação.")
    return user


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if auth.session_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form(default="/")):
    user = auth.authenticate(username, password)
    if not user:
        audit_event("login_failed", actor=username, client_ip=client_ip(request), action="login",
                    outcome="denied", request_id=getattr(request.state, "request_id", None))
        return templates.TemplateResponse(request, "login.html", {"error": "Credenciais inválidas."}, status_code=401)
    request.session.clear()
    request.session.update({"user_id": user.id, "session_version": user.session_version,
                            "csrf_token": auth.secrets.token_urlsafe(32)})
    audit_event("login_success", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="login", request_id=getattr(request.state, "request_id", None))
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
    return RedirectResponse(safe_next, status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    user = guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    request.session.clear()
    audit_event("logout", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="logout", request_id=getattr(request.state, "request_id", None))
    return RedirectResponse("/login", status_code=303)


@router.get("/public/tokens/{public_token}", response_class=HTMLResponse)
def public_token(public_token: str, request: Request):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT name, created_at, confirmed_at, public_link_active, id FROM tokens WHERE public_token=?",
            (public_token,),
        ).fetchone()
        if row is None or not row["public_link_active"]:
            raise HTTPException(404, "Registro não encontrado.")
        opens = conn.execute("SELECT opened_at FROM opens WHERE token_id=? ORDER BY opened_at", (row["id"],)).fetchall()
    finally:
        conn.close()
    audit_event("public_token_viewed", actor="guest", actor_role="guest", client_ip=client_ip(request),
                action="view", target_type="public_token", target_id=public_token,
                request_id=getattr(request.state, "request_id", None))
    return templates.TemplateResponse(request, "public_token.html", {"token": row, "opens": opens}, headers={
        "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow",
    })


@router.get("/ui/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = admin_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    conn = get_connection()
    try:
        users = conn.execute("SELECT id,username,role,is_active,created_at FROM users ORDER BY username").fetchall()
    finally:
        conn.close()
    return templates.TemplateResponse(request, "users.html", {
        "current_user": user, "csrf_token": auth.csrf_token(request), "users": users,
        "api_tokens": auth.list_api_tokens(),
    })


@router.post("/ui/users")
def add_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form(...), csrf_token: str = Form(...)):
    user = admin_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    created = auth.create_user(username, password, role)  # type: ignore[arg-type]
    audit_event("user_created", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="create_user", target_type="user", target_id=created.id,
                request_id=getattr(request.state, "request_id", None))
    return RedirectResponse("/ui/users", 303)


@router.post("/ui/users/{user_id}")
def update_user(request: Request, user_id: int, role: str = Form(...), is_active: str | None = Form(None), csrf_token: str = Form(...)):
    user = admin_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    updated = auth.update_user(user_id, role, is_active == "on")  # type: ignore[arg-type]
    audit_event("user_updated", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="update_user", target_type="user", target_id=updated.id,
                request_id=getattr(request.state, "request_id", None))
    return RedirectResponse("/ui/users", 303)


@router.post("/ui/users/{user_id}/password")
def reset_user_password(
    request: Request,
    user_id: int,
    new_password: str = Form(...),
    password_confirmation: str = Form(...),
    csrf_token: str = Form(...),
):
    user = admin_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    if new_password != password_confirmation:
        raise HTTPException(status_code=400, detail="A confirmação da nova senha não coincide.")
    conn = get_connection()
    try:
        target = auth.update_password(conn, user_id, new_password)
        conn.commit()
    finally:
        conn.close()
    audit_event("password_reset_by_admin", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="reset_user_password", target_type="user", target_id=target.id,
                request_id=getattr(request.state, "request_id", None))
    if target.id == user.id:
        request.session.clear()
        return RedirectResponse("/login", 303)
    return RedirectResponse("/ui/users", 303)


@router.post("/ui/users/{user_id}/api-tokens")
def issue_api_token(request: Request, user_id: int, label: str = Form(""), csrf_token: str = Form(...)):
    user = admin_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    conn = get_connection()
    try:
        target = auth.get_user(conn, user_id)
    finally:
        conn.close()
    if target is None or not target.is_active:
        raise HTTPException(400, "Usuário inválido ou inativo.")
    token_id, raw_token = auth.issue_api_token(user_id, label)
    audit_event("api_token_issued", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="issue_api_token", target_type="api_token", target_id=token_id,
                request_id=getattr(request.state, "request_id", None))
    return HTMLResponse(f"<p>Copie agora; este token não será mostrado de novo:</p><pre>{raw_token}</pre><p><a href='/ui/users'>Voltar</a></p>")


@router.post("/ui/api-tokens/{token_id}/revoke")
def revoke_api_token(request: Request, token_id: int, csrf_token: str = Form(...)):
    user = admin_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    auth.verify_csrf(request, csrf_token)
    auth.revoke_api_token(token_id)
    audit_event("api_token_revoked", actor=user.username, actor_role=user.role, client_ip=client_ip(request),
                action="revoke_api_token", target_type="api_token", target_id=token_id,
                request_id=getattr(request.state, "request_id", None))
    return RedirectResponse("/ui/users", 303)


@router.get("/openapi.json")
def openapi_json(request: Request):
    user = docs_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    return JSONResponse(request.app.openapi())


@router.get("/docs", response_class=HTMLResponse)
def docs(request: Request):
    user = docs_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Email Tracker API")


@router.get("/redoc", response_class=HTMLResponse)
def redoc(request: Request):
    user = docs_guard(request)
    if isinstance(user, RedirectResponse):
        return user
    return get_redoc_html(openapi_url="/openapi.json", title="Email Tracker API")
