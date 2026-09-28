import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import BASE_DIR
from app.db import init_db
from app.logging_config import APP_LOGGER_NAME, configure_logging
from app.request_logging import AccessLogMiddleware
from app.routers import emails, pixel, tokens, ui

configure_logging()
logger = logging.getLogger(APP_LOGGER_NAME)

app = FastAPI(title="Email Tracker")
app.add_middleware(AccessLogMiddleware)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")

app.include_router(tokens.router)
app.include_router(pixel.router)
app.include_router(emails.router)
app.include_router(ui.router)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("application started", extra={"event": "application_startup"})


@app.on_event("shutdown")
def on_shutdown():
    logger.info("application stopped", extra={"event": "application_shutdown"})
