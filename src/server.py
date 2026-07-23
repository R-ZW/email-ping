import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import FastAPI, Request, Response, BackgroundTasks
import sqlite3
import uuid
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

DB = "tracking.db"

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

# Em qual abertura (N-ésima) o alerta deve ser disparado.
# Use 2 (padrão) para ignorar a 1ª abertura, que costuma ser um pre-fetch
# automático de scanners de segurança / proxies de imagem de clientes de
# email (Gmail Image Proxy, Outlook Safe Links, antivírus corporativo etc.),
# e só alertar quando um humano de fato abrir.
# Use 1 para alertar já na primeira abertura (comportamento antigo).
# Use None para alertar em TODAS as aberturas.
ALERT_ON_OPEN_NUMBER = 2

# PNG transparente 1x1
PIXEL = bytes(
    [
        137,
        80,
        78,
        71,
        13,
        10,
        26,
        10,
        0,
        0,
        0,
        13,
        73,
        72,
        68,
        82,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        1,
        8,
        6,
        0,
        0,
        0,
        31,
        21,
        196,
        137,
        0,
        0,
        0,
        13,
        73,
        68,
        65,
        84,
        120,
        156,
        99,
        248,
        255,
        255,
        63,
        0,
        5,
        254,
        2,
        254,
        167,
        53,
        129,
        132,
        0,
        0,
        0,
        0,
        73,
        69,
        78,
        68,
        174,
        66,
        96,
        130,
    ]
)


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        recipient_email TEXT,
        alert_email TEXT
    )
    """)

    # Migração leve para bancos já existentes criados com o schema antigo
    existing_cols = {
        row[1] for row in cur.execute("PRAGMA table_info(tokens)").fetchall()
    }
    if "recipient_email" not in existing_cols:
        cur.execute("ALTER TABLE tokens ADD COLUMN recipient_email TEXT")
    if "alert_email" not in existing_cols:
        cur.execute("ALTER TABLE tokens ADD COLUMN alert_email TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS opens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL,
        opened_at TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_opens_token ON opens(token)
    """)

    conn.commit()
    conn.close()


init_db()


def send_alert_email(
    name: str,
    token: str,
    opened_at: str,
    ip: str,
    user_agent: str,
    alert_to: str,
    recipient_email: str | None,
):
    """Envia email de confirmação de leitura para o destinatário do alerta configurado no token."""
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("[alerta] GMAIL_USER/GMAIL_APP_PASSWORD não configurados, pulando envio.")
        return

    if not alert_to:
        print(
            f"[alerta] Nenhum alert_email definido para o token {token}, pulando envio."
        )
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"📬 Email aberto: {name}"
    msg["From"] = GMAIL_USER
    msg["To"] = alert_to

    linha_destinatario = (
        f"<li><b>Destinatário original:</b> {recipient_email}</li>"
        if recipient_email
        else ""
    )

    corpo = f"""
    <html>
      <body>
        <p>O email <b>{name}</b> foi aberto.</p>
        <ul>
          {linha_destinatario}
          <li><b>Token:</b> {token}</li>
          <li><b>Horário (UTC):</b> {opened_at}</li>
          <li><b>IP:</b> {ip}</li>
          <li><b>User-Agent:</b> {user_agent}</li>
        </ul>
      </body>
    </html>
    """

    msg.attach(MIMEText(corpo, "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, alert_to, msg.as_string())
        print(f"[alerta] Email de confirmação enviado para {alert_to} (token={token})")
    except Exception as e:
        # Não deixamos uma falha no envio de alerta derrubar o endpoint do pixel
        print(f"[alerta] Falha ao enviar email de confirmação: {e}")


@app.get("/create/{name}")
def create_tracking(
    name: str, recipient_email: str | None = None, alert_email: str | None = None
):
    """
    Cria um novo token de rastreamento.

    - recipient_email: email do destinatário para quem este token será enviado
      (apenas informativo, aparece no alerta de leitura).
    - alert_email: para quem enviar o aviso de "email aberto". Se omitido,
      usa GMAIL_USER (o remetente configurado no .env).
    """

    token = str(uuid.uuid4())

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO tokens(token, name, created_at, recipient_email, alert_email)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            token,
            name,
            datetime.now(timezone.utc).isoformat(),
            recipient_email,
            alert_email or GMAIL_USER,
        ),
    )

    conn.commit()
    conn.close()

    return {
        "id": token,
        "name": name,
        "recipient_email": recipient_email,
        "alert_email": alert_email or GMAIL_USER,
    }


@app.get("/pixel/{token}")
def pixel(token: str, request: Request, background_tasks: BackgroundTasks):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    # Busca os dados associados ao token (para o email de alerta)
    cur.execute(
        "SELECT name, recipient_email, alert_email FROM tokens WHERE token = ?",
        (token,),
    )
    row = cur.fetchone()
    if row:
        name, recipient_email, alert_email = row
    else:
        name, recipient_email, alert_email = "(token desconhecido)", None, GMAIL_USER

    # Verifica se já existia alguma abertura antes desta (para decidir se alerta)
    cur.execute("SELECT COUNT(*) FROM opens WHERE token = ?", (token,))
    previous_opens = cur.fetchone()[0]

    opened_at = datetime.now(timezone.utc).isoformat()
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

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
        (token, opened_at, ip, user_agent),
    )

    conn.commit()
    conn.close()

    current_open_number = (
        previous_opens + 1
    )  # esta abertura, contando a que acabou de ser inserida

    should_alert = (
        True
        if ALERT_ON_OPEN_NUMBER is None
        else current_open_number == ALERT_ON_OPEN_NUMBER
    )

    if should_alert:
        background_tasks.add_task(
            send_alert_email,
            name,
            token,
            opened_at,
            ip,
            user_agent,
            alert_email,
            recipient_email,
        )

    return Response(
        content=PIXEL,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
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
        (token,),
    )

    rows = cur.fetchall()

    conn.close()

    return {"token": token, "open_count": len(rows), "opens": [r[0] for r in rows]}
