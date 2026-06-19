import os
import smtplib
import argparse
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

load_dotenv()

gmail_user = os.getenv("GMAIL_USER")
gmail_app_password = os.getenv("GMAIL_APP_PASSWORD")

def enviar_email(server, destinatario, token):

    msg = MIMEMultipart("alternative")

    msg["Subject"] = "Teste de email com tracking"
    msg["From"] = gmail_user
    msg["To"] = destinatario

    # HTML do email
    html = f"""
    <html>
      <body>
        <p>Olá!</p>

        <p>Este é um email de teste.</p>

        <!-- PIXEL DE TRACKING -->
        <img
            src="{server}/pixel/{token}"
            width="1"
            height="1"
            style="opacity:0;"
        />
      </body>
    </html>
    """

    msg.attach(MIMEText(html, "html"))

    # conexão SMTP com Gmail
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()

    server.login(gmail_user, gmail_app_password)

    server.sendmail(
        gmail_user,
        destinatario,
        msg.as_string()
    )

    server.quit()

    print("Email enviado com sucesso!")

def main():
    parser = argparse.ArgumentParser(description="Envio de email com tracking")

    parser.add_argument(
        "-server",
        required=True,
        help="URL do servidor (e.g. https://dominio.com)"
    )

    parser.add_argument(
        "-recipient",
        required=True,
        help="Email do destinatário"
    )

    parser.add_argument(
        "-token",
        required=True,
        help="Token de tracking"
    )

    args = parser.parse_args()

    enviar_email(args.server, args.recipient, args.token)
    

if __name__ == "__main__":
    main()
