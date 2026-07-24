"""
Conexão com o SQLite e definição do schema.

Sem ORM de propósito: o volume de dados é baixo (uso interno) e sqlite3 puro
já é suficiente. Cada request abre e fecha sua própria conexão (get_connection
é usada como dependency do FastAPI, ver main.py).
"""

import sqlite3

from app.config import DATABASE_PATH

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tokens (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    token                   TEXT UNIQUE NOT NULL,
    name                    TEXT NOT NULL,
    recipient_email         TEXT,
    alert_email             TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    confirmed_at            TEXT,
    external_use_marked_at  TEXT,
    external_use_note       TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);

CREATE TABLE IF NOT EXISTS emails (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id      INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    subject       TEXT NOT NULL,
    body_html     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    error_message TEXT,
    created_at    TEXT NOT NULL,
    sent_at       TEXT
);

-- Só permite UMA linha com status='sent' por token. Tentativas 'failed' ou
-- 'pending' não contam pro bloqueio, então reenviar após uma falha é permitido.
CREATE UNIQUE INDEX IF NOT EXISTS idx_emails_token_sent
    ON emails(token_id)
    WHERE status = 'sent';

CREATE INDEX IF NOT EXISTS idx_emails_token_id ON emails(token_id);

CREATE TABLE IF NOT EXISTS attachments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id     INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    content_type TEXT,
    size_bytes   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);

CREATE TABLE IF NOT EXISTS opens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id   INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    opened_at  TEXT NOT NULL,
    ip         TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_opens_token_id_opened_at ON opens(token_id, opened_at);
"""


def get_connection() -> sqlite3.Connection:
    """Abre uma nova conexão com o banco. Uma por request (ver Depends no FastAPI)."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Cria as tabelas/índices caso não existam. Chamado uma vez, no startup da app."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
