from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import BASE_DIR
from app.db import init_db
from app.routers import emails, pixel, tokens, ui

app = FastAPI(title="Email Tracker")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")

app.include_router(tokens.router)
app.include_router(pixel.router)
app.include_router(emails.router)
app.include_router(ui.router)


@app.on_event("startup")
def on_startup():
    init_db()
