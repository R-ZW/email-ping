"""Gera valores de configuração sem expor senhas no histórico do shell."""

import getpass
import secrets
import sys

from cryptography.fernet import Fernet
from pwdlib import PasswordHash


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "password-hash":
        password = getpass.getpass("Senha: ")
        print(PasswordHash.recommended().hash(password))
    elif command == "session-secret":
        print(secrets.token_urlsafe(48))
    elif command == "api-token":
        print("epat_" + secrets.token_urlsafe(32))
    elif command == "smtp-credentials-key":
        print(Fernet.generate_key().decode("ascii"))
    elif command == "reset-password":
        username = sys.argv[2] if len(sys.argv) > 2 else input("Usuário: ").strip()
        password = getpass.getpass("Nova senha: ")
        confirmation = getpass.getpass("Repita a nova senha: ")
        if not username or not password:
            print("Usuário e senha são obrigatórios.")
            raise SystemExit(2)
        if password != confirmation:
            print("As senhas não coincidem.")
            raise SystemExit(2)
        from app.auth import PASSWORD_HASHER, now_iso
        from app.db import get_connection

        conn = get_connection()
        try:
            result = conn.execute(
                """UPDATE users
                   SET password_hash=?, session_version=session_version+1, updated_at=?
                   WHERE username=?""",
                (PASSWORD_HASHER.hash(password), now_iso(), username),
            )
            conn.commit()
        finally:
            conn.close()
        if result.rowcount != 1:
            print("Usuário não encontrado; nenhuma alteração foi feita.")
            raise SystemExit(1)
        print("Senha atualizada. As sessões existentes foram invalidadas.")
    else:
        print("Use: python -m app.credentials password-hash|session-secret|api-token|smtp-credentials-key|reset-password [usuario]")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
