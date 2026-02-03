"""
SBOM API Error Handling
Custom error classes and raise functions for consistent error responses
"""

from fastapi import HTTPException


def raise_validation_error(code: str, message: str, hint: str = None):
    """Raise a validation error (400)"""
    detail = {
        "error": code,
        "message": message
    }
    if hint:
        detail["hint"] = hint
    raise HTTPException(status_code=400, detail=detail)


def raise_upload_error(code: str, message: str, hint: str = None):
    """Raise an upload error (400)"""
    detail = {
        "error": code,
        "message": message
    }
    if hint:
        detail["hint"] = hint
    raise HTTPException(status_code=400, detail=detail)


def raise_api_error(code: str, message: str, status: int = 400):
    """Raise an API error"""
    raise HTTPException(
        status_code=status,
        detail={
            "error": code,
            "message": message
        }
    )


def raise_clone_error(code: str, message: str):
    """Raise a git clone error (500)"""
    raise HTTPException(
        status_code=500,
        detail={
            "error": code,
            "message": message
        }
    )


def raise_error(code: str, message: str, status: int = 400, hint: str = None):
    """General error raise function"""
    detail = {
        "error": code,
        "message": message
    }
    if hint:
        detail["hint"] = hint
    raise HTTPException(status_code=status, detail=detail)
