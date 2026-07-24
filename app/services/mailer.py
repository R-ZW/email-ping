"""
Envio de email via SMTP (Gmail) e montagem do HTML com o pixel de tracking.

Duas responsabilidades principais:
- inject_tracking_pixel: dado um HTML e um token, adiciona o <img> do pixel.
- send_email / send_open_confirmation: montam o MIME e falam com o SMTP.

Isso é chamado tanto pelo /send_email quanto, futuramente, por qualquer outro
fluxo de envio -- por isso fica isolado dos routers.
"""

import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from app.config import GMAIL_APP_PASSWORD, GMAIL_USER, PUBLIC_BASE_URL


class MailerNotConfiguredError(Exception):
    """GMAIL_USER / GMAIL_APP_PASSWORD ausentes no .env."""


def _ensure_configured() -> None:
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise MailerNotConfiguredError(
            "GMAIL_USER/GMAIL_APP_PASSWORD não configurados no .env."
        )


def inject_tracking_pixel(body_html: str, token: str) -> str:
    """Adiciona o <img> do pixel de tracking ao final do HTML fornecido."""
    pixel_url = f"{PUBLIC_BASE_URL}/pixel/{token}"
    pixel_tag = f'<img src="{pixel_url}" width="1" height="1" alt="" />'

    if "</body>" in body_html:
        return body_html.replace("</body>", f"{pixel_tag}</body>")
    return f"{body_html}\n{pixel_tag}"


def send_email(
    to_addr: str,
    subject: str,
    html_body: str,
    attachment_paths: list[Path] | None = None,
) -> None:
    """Envia um email HTML, com anexos opcionais, via Gmail SMTP.

    Levanta MailerNotConfiguredError ou exceções do smtplib -- quem chama
    (o router de /send_email) decide como registrar isso no banco (status='failed').
    """
    _ensure_configured()

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = GMAIL_USER
    msg["To"] = to_addr

    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(html_body, "html"))
    msg.attach(alt_part)

    for path in attachment_paths or []:
        with open(path, "rb") as f:
            part = MIMEApplication(f.read(), Name=path.name)
        part["Content-Disposition"] = f'attachment; filename="{path.name}"'
        msg.attach(part)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, to_addr, msg.as_string())


def send_open_confirmation(
    alert_to: str,
    name: str,
    token: str,
    opened_at: str,
    ip: str | None,
    user_agent: str | None,
    recipient_email: str | None,
) -> None:
    """Envia o email de 'confirmação de leitura' para quem deve ser avisado.

    Disparado manualmente (rota /confirm/{token}), não mais automaticamente
    a partir de uma contagem de aberturas.
    """
    _ensure_configured()

    linha_destinatario = (
        f"<li><b>Destinatário original:</b> {recipient_email}</li>" if recipient_email else ""
    )

    html_body = f"""
    <html>
      <body>
        <p>O email <b>{name}</b> foi confirmado como aberto.</p>
        <ul>
          {linha_destinatario}
          <li><b>Token:</b> {token}</li>
          <li><b>Horário da abertura confirmada (UTC):</b> {opened_at}</li>
          <li><b>IP:</b> {ip or "desconhecido"}</li>
          <li><b>User-Agent:</b> {user_agent or "desconhecido"}</li>
        </ul>
      </body>
    </html>
    """

    send_email(alert_to, f"📬 Email confirmado como lido: {name}", html_body)
