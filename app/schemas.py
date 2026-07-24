"""Modelos Pydantic para request/response da API. Sem lógica aqui, só formato de dados."""

from typing import Literal, Optional

from pydantic import BaseModel

UsageStatus = Literal["unused", "sent", "external"]


class TokenOut(BaseModel):
    token: str
    name: str
    recipient_email: Optional[str]
    alert_email: str
    created_at: str
    confirmed_at: Optional[str]
    external_use_marked_at: Optional[str]
    external_use_note: Optional[str]
    usage_status: UsageStatus


class MarkExternalRequest(BaseModel):
    note: Optional[str] = None


class OpenOut(BaseModel):
    opened_at: str
    ip: Optional[str]
    user_agent: Optional[str]
    seconds_since_created: Optional[float]


class OpensListOut(BaseModel):
    token: str
    open_count: int
    opens: list[OpenOut]


class EmailOut(BaseModel):
    id: int
    subject: str
    status: Literal["pending", "sent", "failed"]
    error_message: Optional[str]
    created_at: str
    sent_at: Optional[str]
    attachments: list[str]
