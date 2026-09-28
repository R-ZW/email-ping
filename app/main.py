import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import bootstrap_admin_and_migrate_tokens
from app.config import BASE_DIR, SESSION_COOKIE_SECURE, SESSION_MAX_AGE_SECONDS, SESSION_SECRET
from app.db import init_db
from app.logging_config import APP_LOGGER_NAME, configure_logging
from app.request_logging import AccessLogMiddleware
from app.routers import emails, pixel, tokens, ui
from app.routers import security

configure_logging()
logger = logging.getLogger(APP_LOGGER_NAME)

app = FastAPI(title="Email Tracker", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(AccessLogMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET or "invalid-unconfigured-secret", max_age=SESSION_MAX_AGE_SECONDS, same_site="lax", https_only=SESSION_COOKIE_SECURE)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")

app.include_router(tokens.router)
app.include_router(pixel.router)
app.include_router(emails.router)
app.include_router(ui.router)
app.include_router(security.router)


@app.on_event("startup")
def on_startup():
    init_db()
    bootstrap_admin_and_migrate_tokens()
    logger.info("application started", extra={"event": "application_startup"})


@app.on_event("shutdown")
def on_shutdown():
    logger.info("application stopped", extra={"event": "application_shutdown"})
