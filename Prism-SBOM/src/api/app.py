"""FastAPI app factory and setup."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from src.config.config import TOOL_NAME, TOOL_VERSION
from src.api.handlers import register_exception_handlers
from src.api.services.session_state import (
    get_session,
    set_current_session,
    clear_current_session,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title=f"{TOOL_NAME} API",
        description="SBOM Generator and Vulnerability Scanner - Step-by-Step Workflow",
        version=TOOL_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    @app.middleware("http")
    async def session_middleware(request: Request, call_next):
        path = request.url.path

        # Allow public endpoints without session
        if path in {"/", "/docs", "/redoc", "/openapi.json"}:
            return await call_next(request)

        token = request.headers.get("X-Session-Token") or request.query_params.get("session_token")

        # /select_source is allowed without token (it creates one)
        if path == "/select_source":
            if token:
                data = get_session(token)
                if not data:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "message": "Invalid session token",
                            "error": "Session not found. Call /select_source to start a new session",
                        },
                    )
                set_current_session(token, data)
            else:
                clear_current_session()
            response = await call_next(request)
            clear_current_session()
            return response

        if not token:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "Missing session token",
                    "error": "Provide X-Session-Token header or session_token query param. Call /select_source first.",
                },
            )

        data = get_session(token)
        if not data:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "Invalid session token",
                    "error": "Session not found. Call /select_source to start a new session",
                },
            )

        set_current_session(token, data)
        response = await call_next(request)
        clear_current_session()
        return response

    return app


app = create_app()
