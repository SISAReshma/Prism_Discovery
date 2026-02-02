"""API exception handlers."""

from __future__ import annotations

from fastapi import HTTPException, Request, FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle Pydantic validation errors with custom format"""
        errors = exc.errors()

        for error in errors:
            if "source_type" in error.get("loc", []):
                return JSONResponse(
                    status_code=400,
                    content={
                        "message": "Selection failed",
                        "error": "Invalid source type. Allowed: repository, zip_file, folder",
                    },
                )

        error_messages = []
        for error in errors:
            field = ".".join(str(loc) for loc in error.get("loc", []) if loc != "body")
            msg = error.get("msg", "Invalid value")
            error_messages.append(f"{field}: {msg}")

        return JSONResponse(
            status_code=400,
            content={
                "message": "Validation failed",
                "error": "; ".join(error_messages) if error_messages else "Invalid request body",
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Catch all unhandled exceptions and return a consistent error response"""
        import traceback

        error_detail = str(exc)
        print(f"[ERROR] Unhandled exception: {error_detail}")
        traceback.print_exc()

        return JSONResponse(
            status_code=500,
            content={
                "message": "Internal server error",
                "error": error_detail,
                "hint": "Please check server logs for more details or try again",
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions with consistent format"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "message": "Request failed",
                "error": exc.detail,
            },
        )
