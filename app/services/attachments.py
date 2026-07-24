"""Salvamento de anexos de email em disco. O banco guarda só o caminho (file_path)."""

from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.config import ATTACHMENTS_DIR, MAX_ATTACHMENT_SIZE_BYTES


@dataclass
class SavedAttachment:
    filename: str
    file_path: Path
    content_type: str | None
    size_bytes: int


def save_attachments(email_id: int, files: list[UploadFile]) -> list[SavedAttachment]:
    """Salva cada arquivo em attachments/{email_id}/{filename} e retorna os metadados.

    Levanta HTTPException(413) se algum arquivo exceder MAX_ATTACHMENT_SIZE_BYTES.
    Em caso de erro no meio do caminho, os arquivos já salvos desta chamada são
    removidos para não deixar anexos "órfãos" em disco.
    """
    email_dir = ATTACHMENTS_DIR / str(email_id)
    email_dir.mkdir(parents=True, exist_ok=True)

    saved: list[SavedAttachment] = []
    try:
        for upload in files:
            if not upload.filename:
                continue

            dest_path = email_dir / Path(upload.filename).name  # remove path traversal
            content = upload.file.read()

            if len(content) > MAX_ATTACHMENT_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Anexo '{upload.filename}' excede o limite de "
                        f"{MAX_ATTACHMENT_SIZE_BYTES // (1024 * 1024)}MB."
                    ),
                )

            dest_path.write_bytes(content)
            saved.append(
                SavedAttachment(
                    filename=upload.filename,
                    file_path=dest_path,
                    content_type=upload.content_type,
                    size_bytes=len(content),
                )
            )
    except Exception:
        for item in saved:
            item.file_path.unlink(missing_ok=True)
        raise

    return saved
