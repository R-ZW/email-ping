from fastapi import FastAPI, Request, Response
from pprint import pprint
import sqlite3
import uuid
from datetime import datetime

app = FastAPI()

DB = "tracking.db"

# PNG transparente 1x1
PIXEL = bytes([
    137,80,78,71,13,10,26,10,
    0,0,0,13,73,72,68,82,
    0,0,0,1,0,0,0,1,
    8,6,0,0,0,31,21,196,
    137,0,0,0,13,73,68,65,
    84,120,156,99,248,255,255,
    63,0,5,254,2,254,167,
    53,129,132,0,0,0,0,
    73,69,78,68,174,66,96,130
])


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS opens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL,
        opened_at TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


@app.get("/create/{name}")
def create_tracking(name: str):

    token = str(uuid.uuid4())

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO tokens(token, name, created_at)
        VALUES (?, ?, ?)
        """,
        (
            token,
            name,
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return {
        "id": token,
        "name": name,
    }


@app.get("/pixel/{token}")
def pixel(
    token: str,
    request: Request
):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO opens(
            token,
            opened_at,
            ip,
            user_agent
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            token,
            datetime.utcnow().isoformat(),
            request.client.host,
            request.headers.get("user-agent")
        )
    )

    conn.commit()
    conn.close()


    return Response(
        content=PIXEL,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache"
        }
    )


@app.get("/opens/{token}")
def get_opens(token: str):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT opened_at
        FROM opens
        WHERE token = ?
        ORDER BY opened_at
        """,
        (token,)
    )

    rows = cur.fetchall()

    conn.close()

    return {
        "token": token,
        "open_count": len(rows),
        "opens": [r[0] for r in rows]
    }