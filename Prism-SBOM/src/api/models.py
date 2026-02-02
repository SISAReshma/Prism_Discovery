"""Pydantic models and enums for API requests."""

from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class SourceTypeEnum(str, Enum):
    """Supported source types for scanning"""
    REPOSITORY = "repository"
    ZIP_FILE = "zip_file"
    FOLDER = "folder"


class SelectSourceRequest(BaseModel):
    source_type: SourceTypeEnum = Field(
        ..., description="Type of source to scan: repository, zip_file, folder"
    )


class UploadRepositoryRequest(BaseModel):
    repository_url: str = Field(..., description="Git repository URL")


class SetTokenRequest(BaseModel):
    token: str = Field(..., description="Personal Access Token for private repos")
