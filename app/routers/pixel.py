import sqlite3
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Request, Response

from app.constants import TRACKING_PIXEL_PNG
from app.db import get_connection

router = APIRouter(tags=["pixel"])

_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


@router.get("/pixel/{token}")
def pixel(
    token: str, request: Request, conn: sqlite3.Connection = Depends(get_connection)
):
    """Registra uma abertura e retorna o PNG 1x1.

    Não decide mais nada sobre "é a Nª abertura" -- isso virou responsabilidade
    humana, exercida depois via /opens/{token} (ver dados) + /confirm/{token} (ação).
    Se o token não existir, a imagem ainda é retornada normalmente (o cliente de
    email não pode notar diferença), só não fica nada registrado no banco.
    """
    token_row = conn.execute(
        "SELECT id FROM tokens WHERE token = ?", (token,)
    ).fetchone()

    if token_row is not None:
        conn.execute(
            "INSERT INTO opens(token_id, opened_at, ip, user_agent) VALUES (?, ?, ?, ?)",
            (
                token_row["id"],
                datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(),
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
            ),
        )
        conn.commit()

    return Response(
        content=TRACKING_PIXEL_PNG,
        media_type="image/png",
        headers=_NO_CACHE_HEADERS,
    )
