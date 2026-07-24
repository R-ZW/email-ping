import sqlite3

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR
from app.db import get_connection
from app.routers.emails import confirm_open, send_email
from app.routers.tokens import create_tracking, mark_external, unmark_external
from app.schemas import MarkExternalRequest
from app.services import token_status
from app.services.emails_view import list_emails_for_token
from app.services.opens_view import list_opens_for_token

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


@router.get("/", response_class=HTMLResponse)
def ui_tokens_list(request: Request, conn: sqlite3.Connection = Depends(get_connection)):
    rows = token_status.list_tokens(conn)
    return templates.TemplateResponse(
        request, "tokens_list.html", {"tokens": rows}
    )


@router.get("/ui/tokens/{token}", response_class=HTMLResponse)
def ui_token_detail(
    token: str, request: Request, conn: sqlite3.Connection = Depends(get_connection)
):
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    usage_status = token_status.get_usage_status(conn, token_row)
    opens = list_opens_for_token(conn, token_row)
    emails = list_emails_for_token(conn, token_row.id)

    return templates.TemplateResponse(
        request,
        "token_detail.html",
        {
            "token_row": token_row,
            "usage_status": usage_status,
            "opens": opens,
            "emails": emails,
        },
    )


@router.post("/ui/tokens/{token}/confirm")
def ui_confirm(token: str, conn: sqlite3.Connection = Depends(get_connection)):
    confirm_open(token, conn)
    return RedirectResponse(url=f"/ui/tokens/{token}", status_code=303)


@router.post("/ui/tokens/{token}/mark_external")
def ui_mark_external(
    token: str,
    note: str = Form(default=""),
    conn: sqlite3.Connection = Depends(get_connection),
):
    mark_external(token, MarkExternalRequest(note=note or None), conn)
    return RedirectResponse(url=f"/ui/tokens/{token}", status_code=303)


@router.post("/ui/tokens/{token}/unmark_external")
def ui_unmark_external(token: str, conn: sqlite3.Connection = Depends(get_connection)):
    unmark_external(token, conn)
    return RedirectResponse(url=f"/ui/tokens/{token}", status_code=303)


@router.get("/ui/new", response_class=HTMLResponse)
def ui_new_token_form(request: Request):
    return templates.TemplateResponse(request, "new_token.html", {})


@router.post("/ui/new")
def ui_create_token(
    name: str = Form(...),
    recipient_email: str = Form(default=""),
    alert_email: str = Form(default=""),
    conn: sqlite3.Connection = Depends(get_connection),
):
    result = create_tracking(
        name=name,
        recipient_email=recipient_email or None,
        alert_email=alert_email or None,
        conn=conn,
    )
    return RedirectResponse(url=f"/ui/tokens/{result.token}", status_code=303)


@router.get("/ui/send/{token}", response_class=HTMLResponse)
def ui_send_email_form(
    token: str, request: Request, conn: sqlite3.Connection = Depends(get_connection)
):
    try:
        token_row = token_status.get_token_or_raise(conn, token)
    except token_status.TokenNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        token_status.ensure_can_send(conn, token_row)
        blocked_reason = None
    except token_status.TokenAlreadyUsedError as exc:
        blocked_reason = exc.detail

    return templates.TemplateResponse(
        request,
        "send_email_editor.html",
        {"token_row": token_row, "blocked_reason": blocked_reason},
    )


@router.post("/ui/send/{token}")
def ui_send_email_submit(
    token: str,
    subject: str = Form(...),
    body_html: str = Form(...),
    files: list[UploadFile] = File(default=[]),
    conn: sqlite3.Connection = Depends(get_connection),
):
    send_email(token=token, subject=subject, body_html=body_html, files=files, conn=conn)
    return RedirectResponse(url=f"/ui/tokens/{token}", status_code=303)
