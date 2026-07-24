"""
Configuração central da aplicação.

Tudo que vem de variável de ambiente é lido aqui, uma única vez, e exposto
como constantes simples. Nenhum outro módulo deve chamar os.getenv() ou
load_dotenv() diretamente -- isso evita ficar espalhado e facilita saber
"de onde vem" cada configuração.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Raiz do projeto (pasta que contém "app/"), resolvida a partir deste arquivo.
# Importante: não depende do diretório de onde o processo foi iniciado.
BASE_DIR = Path(__file__).resolve().parent.parent

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

# URL pública usada para montar o link do pixel embutido no email
# (ex: http://localhost:8000/pixel/<token>)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")

_database_path_env = os.getenv("DATABASE_PATH")
DATABASE_PATH = Path(_database_path_env) if _database_path_env else BASE_DIR / "tracking.db"

_attachments_dir_env = os.getenv("ATTACHMENTS_DIR")
ATTACHMENTS_DIR = Path(_attachments_dir_env) if _attachments_dir_env else BASE_DIR / "attachments"
ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)

MAX_ATTACHMENT_SIZE_BYTES = int(os.getenv("MAX_ATTACHMENT_SIZE_BYTES", 10 * 1024 * 1024))
